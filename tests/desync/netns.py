#!/usr/bin/env python3
"""Exercise the installed desync outbound across a real Linux router.

Run as root: python3 tests/desync/netns.py --binary /path/to/sing-box
Needs iproute2, nftables, tcpdump, openssl and Python 3 (no Python packages).
Every namespace, process, certificate and capture belongs to this run.
"""

import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


REQUEST_BODY = b"desync body:\x00\x01\xff\n"
REQUEST = b"POST /desync HTTP/1.1\r\nHost: stream.example.com\r\nConnection: close\r\nContent-Length: " + str(len(REQUEST_BODY)).encode() + b"\r\n\r\n" + REQUEST_BODY
STUN = struct.pack("!HHI12s", 1, 0, 0x2112A442, b"forkop-probe")
MODES = (
    "none", "split", "disorder", "tlsrec", "fake", "fake_split", "oob",
    "multi_split", "fake_disorder", "multi_disorder", "disoob", "hostfakesplit",
)
SERVER_HOST = "10.231.2.2"
SERVER_FAMILY = socket.AF_INET


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def receive_all(conn):
    data = bytearray()
    while True:
        part = conn.recv(65536)
        if not part:
            return bytes(data)
        data.extend(part)
        if len(data) > 1048576:
            raise RuntimeError("response exceeded the test limit")


def packets(path):
    """Read Ethernet/IPv4 frames from tcpdump's classic pcap format."""
    data = path.read_bytes()
    if len(data) < 24:
        raise RuntimeError("packet capture has no header")
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise RuntimeError("capture must use Ethernet link type")
    offset = 24
    result = []
    while offset + 16 <= len(data):
        length = struct.unpack_from(endian + "I", data, offset + 8)[0]
        frame = data[offset + 16:offset + 16 + length]
        offset += 16 + length
        if len(frame) < 34:
            continue
        ip = frame[14:]
        if frame[12:14] == b"\x08\x00":
            ihl = (ip[0] & 15) * 4
            ip = ip[:struct.unpack_from("!H", ip, 2)[0]]
            if socket.inet_ntoa(ip[16:20]) != SERVER_HOST:
                continue
            protocol, ttl, address_bytes = ip[9], ip[8], ip[12:20]
            fragment = struct.unpack_from("!H", ip, 6)[0]
            if fragment & 0x3FFF:
                result.append({"protocol": "fragment", "offset": fragment & 0x1FFF, "more": bool(fragment & 0x2000)})
            if fragment & 0x1FFF:
                continue
        elif frame[12:14] == b"\x86\xdd" and len(ip) >= 40:
            ip = ip[:40 + struct.unpack_from("!H", ip, 4)[0]]
            if socket.inet_ntop(socket.AF_INET6, ip[24:40]) != SERVER_HOST:
                continue
            ihl, protocol, ttl, address_bytes = 40, ip[6], ip[7], ip[8:40]
            skip = False
            while protocol in (0, 43, 44, 60):
                if ihl + 8 > len(ip):
                    skip = True
                    break
                if protocol == 44:
                    fragment = struct.unpack_from("!H", ip, ihl + 2)[0]
                    result.append({"protocol": "fragment", "offset": fragment >> 3, "more": bool(fragment & 1)})
                    if fragment >> 3:
                        skip = True
                        break
                    length = 8
                else:
                    length = (ip[ihl + 1] + 1) * 8
                protocol, ihl = ip[ihl], ihl + length
            if skip:
                continue
        else:
            continue
        if protocol == 6 and len(ip) >= ihl + 20:
            tcp = ip[ihl:]
            header_length = (tcp[12] >> 4) * 4
            scale = None
            option = 20
            while option < min(len(tcp), header_length):
                kind = tcp[option]
                if kind == 0:
                    break
                if kind == 1:
                    option += 1
                    continue
                if option + 1 >= header_length:
                    break
                length = tcp[option + 1]
                if length < 2 or option + length > header_length:
                    break
                if kind == 3 and length == 3:
                    scale = tcp[option + 2]
                option += length
            pseudo = struct.pack("!BBH", 0, 6, len(tcp)) if SERVER_FAMILY == socket.AF_INET else struct.pack("!I3xB", len(tcp), 6)
            checksum_data = address_bytes + pseudo + tcp
            if len(checksum_data) % 2:
                checksum_data += b"\x00"
            checksum = sum(struct.unpack("!%dH" % (len(checksum_data) // 2), checksum_data))
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            result.append({"protocol": "tcp", "port": struct.unpack_from("!H", tcp, 2)[0], "source_port": struct.unpack_from("!H", tcp)[0], "ttl": ttl, "seq": struct.unpack_from("!I", tcp, 4)[0], "flags": tcp[13], "scale": scale, "checksum_valid": checksum == 65535, "payload": tcp[header_length:]})
        elif protocol == 17 and len(ip) >= ihl + 8:
            udp = ip[ihl:]
            result.append({"protocol": "udp", "port": struct.unpack_from("!H", udp, 2)[0], "source_port": struct.unpack_from("!H", udp)[0], "ttl": ttl, "payload": udp[8:]})
    return result


def server(directory):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(directory / "cert.pem"), str(directory / "key.pem"))

    def handle(conn, tls):
        with conn:
            conn.settimeout(5)
            try:
                if tls:
                    conn = ctx.wrap_socket(conn, server_side=True)
                with conn:
                    data = bytearray()
                    while b"\r\n\r\n" not in data and len(data) < 65536:
                        part = conn.recv(4096)
                        if not part:
                            return
                        data.extend(part)
                    if b"\r\n\r\n" not in data:
                        return
                    header_end = data.index(b"\r\n\r\n") + 4
                    content_length = 0
                    for line in data[:header_end].split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            content_length = int(line.split(b":", 1)[1].strip())
                    if content_length > 65536:
                        return
                    while len(data) < header_end + content_length:
                        part = conn.recv(4096)
                        if not part:
                            return
                        data.extend(part)
                    # Include unexpected trailing bytes, such as an accidentally
                    # repeated request, rather than accepting just its prefix.
                    conn.settimeout(.05)
                    try:
                        while len(data) <= 65536:
                            extra = conn.recv(4096)
                            if not extra:
                                break
                            data.extend(extra)
                    except socket.timeout:
                        pass
                    # The exact request must survive every transformation. A fake
                    # that entered the stream makes this response differ.
                    conn.sendall(b"echo:" + bytes(data))
            except (OSError, ssl.SSLError):
                return

    def tcp(port, tls):
        with socket.socket(SERVER_FAMILY) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("::" if SERVER_FAMILY == socket.AF_INET6 else "0.0.0.0", port))
            listener.listen(32)
            while True:
                conn, _ = listener.accept()
                threading.Thread(target=handle, args=(conn, tls), daemon=True).start()

    for port, tls in ((18080, False), (18443, True)):
        threading.Thread(target=tcp, args=(port, tls), daemon=True).start()
    with socket.socket(SERVER_FAMILY, socket.SOCK_DGRAM) as udp:
        udp.bind(("::" if SERVER_FAMILY == socket.AF_INET6 else "0.0.0.0", 18081))
        while True:
            data, address = udp.recvfrom(65535)
            udp.sendto(data, address)


def exact(conn, n):
    result = bytearray()
    while len(result) < n:
        part = conn.recv(n - len(result))
        if not part:
            raise RuntimeError("SOCKS server closed its response")
        result.extend(part)
    return bytes(result)


def socks(command, port):
    conn = socket.create_connection(("127.0.0.1", 1080), timeout=5)
    conn.sendall(b"\x05\x01\x00")
    if exact(conn, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS authentication rejected")
    address = "0.0.0.0" if command == 3 else SERVER_HOST
    family = socket.AF_INET if command == 3 else SERVER_FAMILY
    conn.sendall(b"\x05" + bytes([command, 0, 1 if family == socket.AF_INET else 4]) + socket.inet_pton(family, address) + struct.pack("!H", port))
    head = exact(conn, 4)
    if head[:2] != b"\x05\x00":
        raise RuntimeError("SOCKS command failed: " + head.hex())
    if head[3] == 1:
        address = socket.inet_ntop(socket.AF_INET, exact(conn, 4))
    elif head[3] == 4:
        address = socket.inet_ntop(socket.AF_INET6, exact(conn, 16))
    else:
        address = exact(conn, exact(conn, 1)[0]).decode()
    port = struct.unpack("!H", exact(conn, 2))[0]
    return conn, (address, port)


def client(protocol):
    if protocol == "stun":
        control, relay = socks(3, 0)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            if relay[0] == "0.0.0.0":
                relay = ("127.0.0.1", relay[1])
            packet = b"\x00\x00\x00" + bytes([1 if SERVER_FAMILY == socket.AF_INET else 4]) + socket.inet_pton(SERVER_FAMILY, SERVER_HOST) + struct.pack("!H", 18081) + STUN
            udp.sendto(packet, relay)
            answer, _ = udp.recvfrom(65535)
            if answer[22 if answer[3] == 4 else 10:] != STUN:
                raise RuntimeError("STUN payload or destination changed")
        return
    conn, _ = socks(1, 18443 if protocol == "tls" else 18080)
    if protocol == "tls":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(conn, server_hostname="stream.example.com")
    with conn:
        conn.sendall(REQUEST)
        answer = receive_all(conn)
        if answer != b"echo:" + REQUEST:
            raise RuntimeError("server received changed, repeated or fake application data: " + repr(answer[:256]))


class Stand:
    def __init__(self, binary, directory):
        self.binary = str(Path(binary).resolve())
        self.directory = directory
        self.names = [f"fd{os.getpid()}{role}" for role in ("c", "r", "s")]
        self.processes = []

    def ip(self, index, *args):
        return run("ip", "-n", self.names[index], *args)

    def spawn(self, index, *args, **kwargs):
        process = subprocess.Popen(["ip", "netns", "exec", self.names[index], *args], **kwargs)
        self.processes.append(process)
        return process

    def setup(self, mtu, nat, impairments):
        for name in self.names:
            run("ip", "netns", "add", name)
        for i in range(3):
            self.ip(i, "link", "set", "lo", "up")
        for a, b, network in ((0, 1, 1), (1, 2, 2)):
            left, right = f"dc{os.getpid()}", f"ds{os.getpid()}"
            run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
            run("ip", "link", "set", left, "netns", self.names[a])
            run("ip", "link", "set", right, "netns", self.names[b])
            for index, interface, host in ((a, left, 1), (b, right, 2)):
                name = f"eth{network}"
                self.ip(index, "link", "set", interface, "name", name)
                self.ip(index, "address", "add", f"10.231.{network}.{host}/24", "dev", name)
                self.ip(index, "-6", "address", "add", f"fd87:231:{network}::{host}/64", "dev", name, "nodad")
                self.ip(index, "link", "set", name, "mtu", str(mtu), "up")
        self.ip(0, "route", "add", "default", "via", "10.231.1.2")
        self.ip(2, "route", "add", "default", "via", "10.231.2.1")
        self.ip(0, "-6", "route", "add", "default", "via", "fd87:231:1::2")
        self.ip(2, "-6", "route", "add", "default", "via", "fd87:231:2::1")
        run("ip", "netns", "exec", self.names[1], "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        run("ip", "netns", "exec", self.names[1], "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
        # Missing marks on either normal or injected packets must cause an
        # actual connection failure, as they would in Forkop's capture rules.
        run("ip", "netns", "exec", self.names[0], "nft", "-f", "-", input="table inet mark_check { chain output { type filter hook output priority filter; ip daddr 10.231.2.2 meta mark != 65280 counter drop; ip6 daddr fd87:231:2::2 meta mark != 65280 counter drop; }; }\n")
        if nat:
            run("ip", "netns", "exec", self.names[1], "nft", "-f", "-", input="table ip test { chain post { type nat hook postrouting priority srcnat; oifname eth2 masquerade; }; }\n")
        if impairments:
            for interface in ("eth1", "eth2"):
                prefix = ("ip", "netns", "exec", self.names[1], "tc")
                run(*prefix, "qdisc", "add", "dev", interface, "root", "handle", "1:", "prio")
                run(*prefix, "qdisc", "add", "dev", interface, "parent", "1:3", "handle", "30:", "netem", "delay", "5ms", "loss", "0.5%", "reorder", "25%", "50%", "gap", "5")
                for priority, family in enumerate(("ip", "ipv6"), 1):
                    run(*prefix, "filter", "add", "dev", interface, "parent", "1:", "protocol", family, "prio", str(priority), "flower", "ip_proto", "tcp", "flowid", "1:3")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=stream.example.com", "-keyout", str(self.directory / "key.pem"), "-out", str(self.directory / "cert.pem"))
        self.spawn(2, sys.executable, str(Path(__file__).resolve()), "--server", str(self.directory), *(["--ipv6"] if SERVER_FAMILY == socket.AF_INET6 else []), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def check(self, name, options, protocol):
        config = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "test", "listen": "127.0.0.1", "listen_port": 1080}],
            "outbounds": [{"type": "desync", "tag": "test-out", "preset": "custom", "auto_tune": False, "routing_mark": 65280, **options}],
            "route": {"final": "test-out"},
        }
        path = self.directory / f"{name}.json"
        path.write_text(json.dumps(config))
        log_path = self.directory / f"{name}.log"
        capture_path = self.directory / f"{name}.pcap"
        capture = self.spawn(1, "tcpdump", "--immediate-mode", "-U", "-n", "-i", "eth1", "-w", str(capture_path), "host", SERVER_HOST, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        capture_deadline = time.monotonic() + 5
        while time.monotonic() < capture_deadline:
            ready, _, _ = select.select([capture.stderr], [], [], .1)
            if ready and b"listening on" in capture.stderr.readline():
                break
            if capture.poll() is not None:
                raise RuntimeError("tcpdump failed to start")
        else:
            raise RuntimeError("tcpdump startup timed out")
        with log_path.open("w") as log:
            process = self.spawn(0, self.binary, "run", "-c", str(path), stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    probe = subprocess.run(["ip", "netns", "exec", self.names[0], sys.executable, "-c", "import socket; socket.create_connection(('127.0.0.1',1080),.1).close()"], capture_output=True)
                    if probe.returncode == 0:
                        break
                    time.sleep(.05)
                else:
                    raise RuntimeError("sing-box failed to listen")
                run("ip", "netns", "exec", self.names[0], sys.executable, str(Path(__file__).resolve()), "--client", protocol, *(["--ipv6"] if SERVER_FAMILY == socket.AF_INET6 else []), timeout=15)
                if protocol == "stun":
                    # Receiving the echo can beat tcpdump's final read/write
                    # when several stands run at once. Wait for capture delivery
                    # before stopping it; all count/TTL assertions stay strict.
                    capture_deadline = time.monotonic() + 2
                    while time.monotonic() < capture_deadline:
                        try:
                            captured = packets(capture_path)
                            if len([p for p in captured if p["protocol"] == "udp" and p["port"] == 18081]) >= 4:
                                break
                        except (OSError, RuntimeError):
                            pass
                        time.sleep(.01)
                self.stop(capture)
                observed = packets(capture_path)
                if protocol == "stun":
                    udp = [p for p in observed if p["protocol"] == "udp" and p["port"] == 18081]
                    if len(udp) != 4 or len({p["source_port"] for p in udp}) != 1:
                        raise RuntimeError("UDP fake count or session source port changed")
                    if [p["ttl"] for p in udp[:3]] != [1, 1, 1] or udp[-1]["payload"] != STUN or udp[-1]["ttl"] <= 1:
                        raise RuntimeError("UDP fake TTL leaked into the original datagram")
                else:
                    port = 18443 if protocol == "tls" else 18080
                    syn = [p for p in observed if p["protocol"] == "tcp" and p["port"] == port and p["flags"] == 2]
                    if "wscale" in options and not any(p["scale"] == options["wscale"] for p in syn if not p["payload"]):
                        raise RuntimeError("SYN does not advertise the configured window scale")
                    if options.get("syndata"):
                        expected = base64.b64decode(options["syndata"])
                        if len(syn) < 2 or syn[0]["payload"] != expected or syn[1]["payload"] or syn[0]["source_port"] != syn[1]["source_port"] or syn[0]["checksum_valid"]:
                            raise RuntimeError("fake SYN payload does not precede the real SYN on its TCP tuple")
                    if options.get("ipfrag") and not any(p["protocol"] == "fragment" and p["more"] for p in observed):
                        raise RuntimeError("capture does not show configured IP fragmentation")
                    tcp = [p for p in observed if p["protocol"] == "tcp" and p["port"] == (18443 if protocol == "tls" else 18080) and p["payload"]]
                    mode = options["mode"]
                    if "fake" in mode and not any(b"fake.example.org" in p["payload"] for p in tcp):
                        raise RuntimeError("fake hostname is missing from the packet capture")
                    if options.get("autottl"):
                        fake = [p for p in tcp if b"fake.example.org" in p["payload"]]
                        if not fake or any(p["ttl"] != 1 for p in fake):
                            raise RuntimeError("autottl did not use the observed route distance")
                    if "disorder" in mode or mode == "disoob":
                        if not any(a["seq"] > b["seq"] for a, b in zip(tcp, tcp[1:])):
                            raise RuntimeError("capture does not show out-of-order TCP segments")
                print(f"PASS {name}", flush=True)
            except Exception as exc:
                detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else ""
                raise RuntimeError(f"{name}: {exc}\n{detail}\n{log_path.read_text()}") from exc
            finally:
                self.stop(process)
                self.stop(capture)

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def close(self):
        for process in reversed(self.processes):
            self.stop(process)
        for name in reversed(self.names):
            subprocess.run(["ip", "netns", "del", name], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--server", type=Path)
    parser.add_argument("--client", choices=("http", "tls", "stun"))
    parser.add_argument("--mtu", type=int, default=1500)
    parser.add_argument("--nat", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--impairments", action="store_true", help="router adds TCP delay (5ms), loss (0.5%%) and reordering")
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    global SERVER_HOST, SERVER_FAMILY
    if args.ipv6:
        SERVER_HOST, SERVER_FAMILY = "fd87:231:2::2", socket.AF_INET6
    if args.server:
        server(args.server)
        return
    if args.client:
        client(args.client)
        return
    if not args.binary:
        parser.error("--binary is required")
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Linux and root (CAP_NET_ADMIN/CAP_NET_RAW) required")
    for command in ("ip", "nft", "openssl", "tcpdump"):
        if not shutil.which(command):
            parser.error(f"missing {command}")
    directory = args.artifacts
    temporary = tempfile.TemporaryDirectory(prefix="forkop-desync-") if directory is None else contextlib.nullcontext(str(directory.resolve()))
    with temporary as location:
        directory = Path(location)
        directory.mkdir(parents=True, exist_ok=True)
        stand = Stand(args.binary, directory)
        try:
            stand.setup(args.mtu, args.nat, args.impairments)
            for mode in args.modes.split(","):
                for protocol in ("tls", "http"):
                    options = {"mode": mode}
                    if mode not in ("none", "fake", "oob"):
                        options["split_pos"] = "1,midsld" if mode.startswith("multi_") else "midsld"
                    if "fake" in mode:
                        options.update(fake_sni="fake.example.org", fake_host="fake.example.org", fooling="badseq")
                    stand.check(f"{mode}-{protocol}", options, protocol)
            stand.check("udp-stun", {"mode": "none", "udp_mode": "stun", "udp_ttl": 1, "udp_repeats": 3, "udp_out_range": "1:2", "udp_keep_socket": True}, "stun")
            stand.check("udp-stun-ephemeral", {"mode": "none", "udp_mode": "stun", "udp_ttl": 1, "udp_repeats": 3, "udp_out_range": "1:2", "udp_keep_socket": False}, "stun")
            for scale in (0, 2, 7, 14):
                stand.check(f"window-scale-{scale}", {"mode": "split", "wscale": scale}, "tls")
            stand.check("syn-data", {"mode": "split", "syndata": base64.b64encode(b"FAKE-SYN-PROBE").decode()}, "tls")
            stand.check("autottl", {"mode": "fake_split", "fake_sni": "fake.example.org", "fake_host": "fake.example.org", "ttl": 3, "autottl": True}, "tls")
            for fooling in ("md5_badack", "badseq_badack_badsum", "datanoack"):
                stand.check(f"fooling-{fooling}", {"mode": "fake_split", "fake_sni": "fake.example.org", "fake_host": "fake.example.org", "fooling": fooling}, "tls")
            stand.check("ip-fragments", {"mode": "split", "ipfrag": 200}, "tls")
            stand.check("sequence-overlap", {"mode": "fake_split", "fake_sni": "fake.example.org", "fake_host": "fake.example.org", "seqovl": 8}, "tls")
            if args.ipv6:
                for fooling in ("hopbyhop", "destopt"):
                    stand.check(f"ipv6-{fooling}", {"mode": "fake_split", "fake_sni": "fake.example.org", "fake_host": "fake.example.org", "fooling": fooling}, "tls")
        finally:
            stand.close()


if __name__ == "__main__":
    main()
