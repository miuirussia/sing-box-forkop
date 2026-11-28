package tlsspoof

import "net"

// DesyncPacket describes one raw TCP segment relative to the initial snd_nxt.
// Fake segments ALWAYS end at or before snd_nxt. Fooling is additional to this
// invariant: a low TTL alone cannot guarantee that fake data stays out of TCP.
type DesyncPacket struct {
	FakeLength int
	Payload    []byte
	Offset     int
	Fake       bool
	// Decoy uses real sequence offsets but is ALWAYS checksum-invalid. It is
	// reserved for length-preserving host substitution, never kernel-queued.
	Decoy    bool
	Fooling  string
	TTL      int
	Window   int
	Fragment int
	Overlap  int
	Urgent   bool
}

// NewDesyncSession requires an established socket which has not carried data.
func NewDesyncSession(conn net.Conn) (*DesyncSession, error) { return newDesyncSession(conn) }
