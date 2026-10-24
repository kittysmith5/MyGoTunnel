package utlsconn

import utls "github.com/refraction-networking/utls"

// One bounded process-wide cache, not an unbounded map of per-endpoint caches.
// Tickets stay in memory and never bypass AUTH or enable application 0-RTT.
var sessions = utls.NewLRUClientSessionCache(64)

type scopedCache struct {
	cache utls.ClientSessionCache
	scope string
}

func (s scopedCache) Get(key string) (*utls.ClientSessionState, bool) {
	return s.cache.Get(s.scope + ":" + key)
}

func (s scopedCache) Put(key string, state *utls.ClientSessionState) {
	s.cache.Put(s.scope+":"+key, state)
}
