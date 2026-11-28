# Linux router stand

`netns.py` creates an isolated client, router and server using network namespaces
and veth links. It runs the actual sing-box binary through a SOCKS inbound, with
the production `desync` outbound. It requires Linux, root/CAP_NET_ADMIN and
CAP_NET_RAW, Python 3, iproute2, nftables, tcpdump and openssl. Python has no extra
dependencies. Processes, links and namespaces are cleaned up on failure as well
as success. It does not change the machine's existing routes or firewall.

Build and run from the repository root:

```sh
go build -tags badlinkname,with_utls,tfogo_checklinkname0,with_clash_api,with_quic \
  -ldflags=-checklinkname=0 -o /tmp/desync-sing-box ./cmd/sing-box
sudo python3 tests/desync/netns.py --binary /tmp/desync-sing-box \
  --artifacts /tmp/desync-packets/plain
sudo python3 tests/desync/netns.py --binary /tmp/desync-sing-box \
  --nat --mtu 1280 --artifacts /tmp/desync-packets/nat
sudo python3 tests/desync/netns.py --binary /tmp/desync-sing-box \
  --ipv6 --artifacts /tmp/desync-packets/ipv6
sudo python3 tests/desync/netns.py --binary /tmp/desync-sing-box \
  --impairments --artifacts /tmp/desync-packets/loss
```

The default run checks every TCP mode with real TLS and HTTP. The server must
receive the exact original request, including its body, with no fake bytes or
repeated application request. Captures assert fake hostnames, reversed sequence
order, IP fragmentation, invalid-checksum SYN payload before the real SYN on the
same tuple, and SYN window scales 0/2/7/14. AutoTTL is tested through the router,
including actual hop-limit observations. IPv6 adds Hop-by-Hop and Destination
Options cases. A firewall in the client namespace drops any target packet that
lost its configured routing mark, including raw packets.

STUN cases assert the exact fake count, fake TTL, preservation of the real
datagram and the session's source port, for both retained and ephemeral fake
sockets. QUIC v1/v2 handshakes, authenticated Initial resizing, packet counters,
STUN authentication and raw packet vectors are covered by the integration tests:

```sh
sudo env "PATH=$PATH" go test -race -tags integration \
  ./common/desync ./common/tlsspoof
```

`--impairments` adds TCP delay, loss and reordering in both router directions.
UDP remains deterministic so a permitted UDP loss cannot turn a source-port or
packet-count assertion into a false failure. `--modes split,fake_split` narrows
the TCP matrix while retaining advanced checks. `--nat` applies IPv4 NAT;
`--ipv6` tests native IPv6. Keep `--artifacts` to retain configurations, logs and
pcaps; otherwise temporary files are removed automatically.

These tests establish transport correctness and socket behavior. Effectiveness
against a particular provider's filtering needs a separate test on that network.

The advanced checks also exercise independent TLS/TCP boundaries, explicit
segment permutations, hostname-last ordering, interleaved randomized/padded fake
bursts, and length-preserving host decoys with mandatory invalid checksums.
