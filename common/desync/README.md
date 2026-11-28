# Desync network engine

`NewConn`, `NewUDPConn` and `NewPacketConn` wrap direct sockets. Pass options
resolved by `option.NormalizeDesyncOptions`; `Validate` also rejects unsupported
combinations. Compose `SocketControl` with the direct dialer's existing controls
**before connect** for SYN data, window scaling and passive route observation.
Direct DNS, interface, namespace and routing-mark controls stay with that dialer.

TCP mode `none` passes through. `split`/`multi_split` write ordered segments;
`tlsrec` adds TLS record headers without changing handshake bytes; disorder modes
send real raw segments in reverse order. Fake variants inject a forged TLS
ClientHello or HTTP request before the real flight; `hostfakesplit` also selects
host-related splitting. OOB modes put the urgent flag/pointer on the fake raw
segment. `tlsrec_first` rebuilds record layout before resolving split positions.

`tlsrec_pos` decouples record cuts from TCP `split_pos`. `segment_order` selects
forward/reverse, hostname-last, or an explicit one-based permutation on the raw
path. `fake_placement` interleaves fake bursts, with independently cancellable
`fake_delay`. TLS fake randomization, exact padding and compact templates affect
only fake ClientHellos. `http_mod` changes only the first HTTP Host header while
retaining body/pipeline bytes. `hostfake_mode=replace` sends a length-preserving
hostname decoy at real sequence offsets with an unconditionally invalid checksum;
ordinary fakes retain their separate sequence-range invariant.

The engine assembles the first ClientHello or HTTP headers across writes, with a
256 KiB buffer and a 250 ms assembly timer. On incomplete timeout or buffer limit
it flushes the original bytes unchanged. Semantic hostname cuts and generated
fakes apply only when the first flight contains a parseable SNI or HTTP Host;
binary handshakes, Host-less HTTP and SNI-less TLS otherwise pass unchanged.
Numeric cuts remain applicable to binary flights. Invalid offsets into an
existing hostname still produce errors. The TLS-record-only mode passes other
protocols unchanged. Later bytes, including HTTP bodies and TLS early data,
are forwarded once; this package never retries a request on another connection.
An error after a partial initial write is terminal. Close and cancellation unblock
I/O and delays; changing a deadline wakes pending delays.

`CloseWrite` unwraps tracking/counter layers and sends FIN while retaining the
read side. Adaptive seals replay at FIN. Its first-flight write deadline covers
segmentation and asynchronous assembly as well as the initial dial; completion
restores the caller's current deadlines for the established stream.

Markers are zero-based wire offsets: `sni`/`host` is the first hostname byte,
`endhost` is immediately after its last byte, `sniext` is the SNI extension type,
`extlen` is the TLS extensions-vector length field. `midsld` is the middle of the
penultimate DNS label, without public-suffix-list interpretation. Signed offsets
and comma-separated, sorted, deduplicated cuts are supported. Numeric positions
are positive absolute wire offsets. TLS record cuts must fall inside a record
payload; splitting inside an existing record header is an error. SNI offsets
remain correct when the handshake already spans multiple records.

Raw TCP requires Linux, an established owned socket, CAP_NET_RAW and
CAP_NET_ADMIN (TCP_REPAIR sequence snapshot). Real raw bytes are subsequently
queued through ordinary TCP writes so the kernel owns ACK and loss recovery.
Duplicates can exist on the wire; the server stream contains one copy. Fake
bytes are never queued on the TCP socket. Every fake sequence range ends before
or at the initial snd_nxt, independently of TTL/checksum/ACK/MD5/timestamp fooling.
Fake segments respect path MTU. The raw socket inherits source address,
SO_BINDTODEVICE and SO_MARK. Combined fooling and IPv6 Hop-by-Hop/Destination
Options work; timestamp fooling requires negotiated timestamps. `seqovl` repeats
known original bytes at adjacent raw segment boundaries. `wsize` changes the raw
first-flight advertised window; subsequent kernel packets advertise the normal
window. IP fragments use 8-byte alignment; IPv6 keeps Hop-by-Hop unfragmentable
and includes the complete transport header in the first fragment.

`syndata` means a checksum-invalid raw SYN carrying 1..1200 fake bytes on the
same tuple immediately before the kernel SYN; it is not application TCP Fast
Open. `wscale` uses per-socket receive space/window clamp before SYN and verifies
the negotiated value. The scale cannot be restored after negotiation. The receive-buffer size is
restored after connect; Linux leaves its manual-buffer lock set, so window-scale
overrides also disable subsequent automatic receive-buffer growth. Linux or
peer limitations fail specifically. The passive autottl observer is bounded,
namespace/tuple-partitioned and cached; it estimates the peer's initial TTL from
64/128/255 and clamps the result to 1..32, capped by configured TTL. Without an
observation, configured fixed TTL is the documented fallback. Reverse-path TTL
can only estimate forward hop distance.

Both UDP APIs preserve the original socket/local port and count datagrams per
destination (maximum 1024 destinations). `udp_out_range` is inclusive and
one-based. Only recognized QUIC Initial/STUN traffic receives fake datagrams;
custom payloads override generated ones. `quic_desync=false` skips QUIC fake
and resizing while keeping STUN active in auto mode; `quic_repeats` overrides
the shared repeat count for QUIC only. TTL changes use the actual datagram's
destination family (including IPv4 on a dual-stack IPv6 socket), are serialized
with writes and restored on every error path. `udp_keep_socket=true` retains the application socket for fake sends; explicit
`false` opens a send-only raw UDP socket for each fake burst, inherits the
session source tuple/mark/interface, and closes it immediately afterwards. The
application socket remains open so replies stay associated. This path requires
Linux and CAP_NET_RAW, and fragments fake datagrams to the discovered path MTU.
Domain NAT must wrap the engine so raw injection sees the configured resolver
result, rather than performing separate DNS lookups.
Darwin supports native IPv4/IPv6 sockets; mapped IPv4 fake TTL on its dual-stack
IPv6 sockets is rejected before mutation because its kernel cannot restore the
original IPv4 TTL safely. Linux supports destination changes on dual-stack sockets.

`udplen` is an exact positive increase of the real datagram length. QUIC Initial
v1/v2/draft29 is decrypted with public Initial keys, padded, re-encrypted and
header-protected; other coalesced packets remain unchanged. Later Initial packets
retain the original key across a peer CID change; Retry/new-key Initial packets
update the protection key after authentication. Handshake/0-RTT/1-RTT packets are never
resized without their traffic secrets. Generated QUIC fakes contain only the
first Initial with an invalid tag, never coalesced application data. STUN PADDING
requires a multiple of four bytes; it follows MESSAGE-INTEGRITY and precedes the
last FINGERPRINT, which is recomputed. Integrity bytes remain unchanged.

Initial keys and packet-number history are isolated by destination and client
SCID, including across server DCID changes and Retry. Each UDP socket retains at
most 1024 connection states until it closes; at capacity, new connections fail
before fake or real sends while existing connections continue. Failed/partial
sends do not commit Initial state. Empty client SCIDs support one connection per
destination, including sequential connections with new keys.

`quic_split_pos` and `quic_order` split/reorder CRYPTO frames within one Initial,
preserving stream offsets, packet number and handshake bytes. Existing PADDING
pays for new frame headers; exhausted datagram budgets fail before sending.
Unresolved semantic markers and unknown frame types pass through unchanged.
Cross-packet CRYPTO reordering is not performed. See `DESYNC.md` for parameters.

Run Linux tests in a privileged environment with tcpdump:

```
go test -race -tags=integration ./common/desync ./common/tlsspoof
```

Tests cover real TLS/HTTP, QUIC v1/v2 through both UDP APIs, STUN Binding and
padding, packet counts, port preservation, cancellation/deadlines, and packet
capture assertions for sequence inversion/overlap, fake rejection, TTL, combined
fooling, IPv4/IPv6 fragments, SYN payload ordering and window scales 0/1/7/14.
