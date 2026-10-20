package socks5

import "testing"

func TestUDPHeaderValidationAndExistingTargetLookupAllocateNothing(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "target.invalid"} {
		packet := BuildUDPDatagram(UDPDatagram{Host: host, Port: 443}, []byte("payload"))
		h, _, err := ParseUDPHeader(packet)
		if err != nil || h.Host() != host {
			t.Fatal(h, err)
		}
		targets := map[string]int{string(packet[3:h.Size]): 1}
		allocations := testing.AllocsPerRun(1000, func() {
			if err := ValidateUDPDatagram(packet); err != nil {
				panic(err)
			}
			header, _, err := ParseUDPHeader(packet)
			if err != nil || targets[string(packet[3:header.Size])] != 1 {
				panic("lost existing target")
			}
		})
		if allocations != 0 {
			t.Fatalf("%s: allocations=%v", host, allocations)
		}
	}
}

func BenchmarkUDPHeader(b *testing.B) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "target.invalid"} {
		b.Run(host, func(b *testing.B) {
			packet := BuildUDPDatagram(UDPDatagram{Host: host, Port: 443}, make([]byte, 1200))
			h, _, _ := ParseUDPHeader(packet)
			targets := map[string]int{string(packet[3:h.Size]): 1}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				header, _, err := ParseUDPHeader(packet)
				if err != nil || targets[string(packet[3:header.Size])] != 1 {
					b.Fatal("header lookup failed", err)
				}
			}
		})
	}
}
