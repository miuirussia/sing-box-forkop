package desync

import "time"

// ttlObservation is shared by the namespace-aware pre-SYN observer.
type ttlObservation struct {
	ttl     int
	expires time.Time
}
