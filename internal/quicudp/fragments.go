package quicudp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"mygotunnel/internal/datagram"
)

const (
	MaxPacketSize     = 65000
	WireDatagramSize  = 1100
	fragmentHeader    = 12
	fragmentPayload   = WireDatagramSize - fragmentHeader
	maxIncomplete     = 16
	recentPacketCount = 64
	defaultMaxAge     = 250 * time.Millisecond
)

var (
	ErrMalformedFragment = errors.New("invalid QUIC UDP fragment")
	ErrFragmentLimit     = errors.New("QUIC UDP fragment limit")
)

// Fragments owns a copy of packet, split into wire datagrams. The header is
// 'Q', version 1, packet ID, total packet length, fragment index and fragment
// count. All multibyte integers are big endian. Chunk positions and lengths are
// derived from the fixed payload size; the receiver never trusts a wire offset.
func Fragments(packet []byte, id uint32) ([][]byte, error) {
	count, err := FragmentCount(len(packet))
	if err != nil {
		return nil, err
	}
	storage := make([]byte, len(packet)+count*fragmentHeader)
	fragments := make([][]byte, count)
	offset := 0
	for i := range fragments {
		n := min(fragmentPayload, len(packet)-i*fragmentPayload)
		frame, err := Fragment(storage[offset:offset+fragmentHeader+n:offset+fragmentHeader+n], packet, id, i)
		if err != nil {
			return nil, err
		}
		fragments[i] = frame
		offset += len(frame)
	}
	return fragments, nil
}

// FragmentCount validates the logical packet size before calculating its wire
// fragment count. A SOCKS UDP envelope is nonempty even for an empty UDP payload.
func FragmentCount(packetSize int) (int, error) {
	if packetSize <= 0 || packetSize > MaxPacketSize {
		return 0, ErrMalformedFragment
	}
	return (packetSize + fragmentPayload - 1) / fragmentPayload, nil
}

// Fragment encodes one fragment into caller-owned scratch without allocation.
// dst must have sufficient capacity and must not alias packet. The returned
// slice aliases dst, so callers must finish consuming it before reusing scratch.
func Fragment(dst []byte, packet []byte, id uint32, index int) ([]byte, error) {
	count, err := FragmentCount(len(packet))
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= count {
		return nil, ErrMalformedFragment
	}
	offset := index * fragmentPayload
	n := min(fragmentPayload, len(packet)-offset)
	if cap(dst) < fragmentHeader+n {
		return nil, io.ErrShortBuffer
	}
	frame := dst[:fragmentHeader+n]
	frame[0], frame[1] = 'Q', 1
	binary.BigEndian.PutUint32(frame[2:6], id)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(packet)))
	binary.BigEndian.PutUint16(frame[8:10], uint16(index))
	binary.BigEndian.PutUint16(frame[10:12], uint16(count))
	copy(frame[fragmentHeader:], packet[offset:offset+n])
	return frame, nil
}

type incompletePacket struct {
	packet   datagram.Packet
	expires  time.Time
	received uint64
	count    int
}

type recentPacket struct {
	id      uint32
	expires time.Time
}

type ReassemblyStats struct {
	ExpiredPackets uint64
}

// Reassembler is single-reader. All payload storage is charged to the shared
// process Resources. Incomplete packets are bounded separately per association;
// missing fragments do not hold up complete packets. Call Expire while idle and
// Close on association shutdown. Completed packets transfer ownership to caller.
type Reassembler struct {
	resources *datagram.Resources
	maxAge    time.Duration
	pending   map[uint32]*incompletePacket
	recent    [recentPacketCount]recentPacket
	recentAt  int
	closed    bool
	stats     ReassemblyStats
}

func NewReassembler(resources *datagram.Resources, maxAge time.Duration) *Reassembler {
	if resources == nil {
		resources = datagram.DefaultResources
	}
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}
	return &Reassembler{resources: resources, maxAge: maxAge, pending: make(map[uint32]*incompletePacket)}
}

func (r *Reassembler) remember(id uint32, now time.Time) {
	r.recent[r.recentAt] = recentPacket{id: id, expires: now.Add(r.maxAge)}
	r.recentAt = (r.recentAt + 1) % len(r.recent)
}

func (r *Reassembler) seen(id uint32, now time.Time) bool {
	for _, p := range r.recent {
		if p.id == id && now.Before(p.expires) {
			return true
		}
	}
	return false
}

// Push drops duplicate or recently expired/completed packets without producing
// data. A malformed fragment, per-association limit or process resource refusal
// is returned distinctly so the transport can count and drop it, not close an
// otherwise healthy association. The first fragment fixes the absolute expiry.
func (r *Reassembler) Push(frame []byte, now time.Time) (datagram.Packet, bool, error) {
	if r.closed {
		return datagram.Packet{}, false, ErrFragmentLimit
	}
	r.Expire(now)
	if len(frame) <= fragmentHeader || len(frame) > WireDatagramSize || frame[0] != 'Q' || frame[1] != 1 {
		return datagram.Packet{}, false, ErrMalformedFragment
	}
	id := binary.BigEndian.Uint32(frame[2:6])
	total := int(binary.BigEndian.Uint16(frame[6:8]))
	index := int(binary.BigEndian.Uint16(frame[8:10]))
	count := int(binary.BigEndian.Uint16(frame[10:12]))
	if total == 0 || total > MaxPacketSize || count != (total+fragmentPayload-1)/fragmentPayload || index >= count {
		return datagram.Packet{}, false, ErrMalformedFragment
	}
	offset := index * fragmentPayload
	if len(frame)-fragmentHeader != min(fragmentPayload, total-offset) {
		return datagram.Packet{}, false, ErrMalformedFragment
	}
	if r.seen(id, now) {
		return datagram.Packet{}, false, nil
	}
	p := r.pending[id]
	if p != nil && (len(p.packet.Data) != total || p.count != count) {
		return datagram.Packet{}, false, ErrMalformedFragment
	}
	if count == 1 {
		// A complete datagram does not need an incomplete-packet slot. Missing
		// older packets must not block ordinary small UDP traffic.
		packet, err := r.resources.Borrow(total)
		if err != nil {
			return datagram.Packet{}, false, err
		}
		copy(packet.Data, frame[fragmentHeader:])
		r.remember(id, now)
		return packet, true, nil
	}
	if p == nil {
		if len(r.pending) >= maxIncomplete {
			return datagram.Packet{}, false, ErrFragmentLimit
		}
		packet, err := r.resources.Borrow(total)
		if err != nil {
			return datagram.Packet{}, false, err
		}
		p = &incompletePacket{packet: packet, expires: now.Add(r.maxAge), count: count}
		r.pending[id] = p
	}
	bit := uint64(1) << index
	dst := p.packet.Data[offset : offset+len(frame)-fragmentHeader]
	if p.received&bit != 0 {
		if !bytes.Equal(dst, frame[fragmentHeader:]) {
			// Conflicting duplicate pieces cannot be safely interpreted. Keep a
			// short tombstone so delayed pieces cannot resurrect this packet.
			p.packet.Release()
			delete(r.pending, id)
			r.remember(id, now)
			return datagram.Packet{}, false, ErrMalformedFragment
		}
		return datagram.Packet{}, false, nil
	}
	copy(dst, frame[fragmentHeader:])
	p.received |= bit
	if p.received != (uint64(1)<<count)-1 {
		return datagram.Packet{}, false, nil
	}
	delete(r.pending, id)
	r.remember(id, now)
	return p.packet, true, nil
}

func (r *Reassembler) Expire(now time.Time) {
	for id, p := range r.pending {
		if !now.Before(p.expires) {
			p.packet.Release()
			delete(r.pending, id)
			r.remember(id, now)
			r.stats.ExpiredPackets++
		}
	}
}

// Stats is a single-reader snapshot, like Push and Expire. Close releases
// incomplete storage without counting normal shutdown as packet expiration.
func (r *Reassembler) Stats() ReassemblyStats { return r.stats }

func (r *Reassembler) Close() {
	if r.closed {
		return
	}
	r.closed = true
	for id, p := range r.pending {
		p.packet.Release()
		delete(r.pending, id)
	}
}
