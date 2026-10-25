package quicudp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	quic "github.com/quic-go/quic-go"
)

// DialOptions separates source-address validation tokens from TLS resumption.
// TokenTrustScope is the caller's explicit CA or leaf-pin policy, using "ca:"
// or "pin:<sha256>". A cached token never authorizes application traffic and
// does not disable the fresh TLS handshake, certificate verification or AUTH.
type DialOptions struct {
	TokenCache      bool
	TokenTrustScope string
	// SocketReserve keeps process-budget capacity for foreground relay sockets.
	SocketReserve int
}

// The library implements mutex-protected LRU eviction and removes each token
// on Pop, as required by QUIC's single-use NEW_TOKEN policy. State is process
// local: no tokens are persisted or included in connection codes or logs.
var sourceAddressTokens = quic.NewLRUTokenStore(16, 4)

type scopedAddressTokens struct {
	store quic.TokenStore
	scope string
}

func (s scopedAddressTokens) key(key string) string {
	value := sha256.Sum256([]byte(s.scope + "\x00" + key))
	return hex.EncodeToString(value[:])
}

func (s scopedAddressTokens) Pop(key string) *quic.ClientToken { return s.store.Pop(s.key(key)) }
func (s scopedAddressTokens) Put(key string, token *quic.ClientToken) {
	s.store.Put(s.key(key), token)
}

func addressTokensFor(remote string, tlsConfig *tls.Config, options []DialOptions) (quic.TokenStore, error) {
	if len(options) > 1 || (len(options) == 1 && options[0].SocketReserve < 0) {
		return nil, fmt.Errorf("invalid QUIC dial options")
	}
	if len(options) == 0 || !options[0].TokenCache {
		return nil, nil
	}
	policy := options[0].TokenTrustScope
	switch {
	case policy == "ca:":
		if tlsConfig.InsecureSkipVerify {
			return nil, fmt.Errorf("invalid QUIC token trust policy")
		}
		// Custom root pools need an explicit policy identifier of their own.
		// Production CA connections use the system roots; keep nonstandard
		// callers uncached rather than infer identity from pointers or subjects.
		if tlsConfig.RootCAs != nil {
			return nil, nil
		}
	case strings.HasPrefix(policy, "pin:"):
		pin, err := hex.DecodeString(strings.TrimPrefix(policy, "pin:"))
		if err != nil || len(pin) != sha256.Size || !tlsConfig.InsecureSkipVerify || tlsConfig.VerifyConnection == nil {
			return nil, fmt.Errorf("invalid QUIC token trust policy")
		}
		policy = "pin:" + hex.EncodeToString(pin)
	default:
		return nil, fmt.Errorf("invalid QUIC token trust policy")
	}
	// quic-go's native key is only SNI (or an IP when absent). Include the
	// configured remote endpoint and trust policy before accepting that key,
	// so ports, SNI and different certificate pins never share token buckets.
	scope := sha256.Sum256([]byte(remote + "\x00" + tlsConfig.ServerName + "\x00" + policy))
	return scopedAddressTokens{store: sourceAddressTokens, scope: hex.EncodeToString(scope[:])}, nil
}
