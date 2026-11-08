#!/usr/bin/env python3
"""Minimal mock SoftEther/SSTP server, for validating vpngate-client's
SSTP+PPP establish and userspace TCP WITHOUT a real VPNGate node.

Behaviour:
- TLS (self-signed) on 127.0.0.1:8443, SSTP_DUPLEX_POST -> 200.
- PPP: LCP Req -> Ack + own Req; PAP -> Ack; IPCP Req -> Ack offering
  virtual IP 10.0.0.2.
- After that, any TCP SYN inside the tunnel gets a SYN+ACK; any data
  gets an ACK plus a canned "HTTP/1.1 204 No Content" reply, so the
  client's generate_204 check passes. (It is a mock: it does not
  forward anything to the real internet.)
"""
import socket, ssl, struct, sys, threading

def csum(data):
    if len(data) % 2: data += b"\x00"
    s = 0
    for i in range(0, len(data), 2): s += (data[i] << 8) | data[i+1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def sstp_data(ppp):
    size = 6 + len(ppp)
    return bytes([0x10, 0x00, ((size >> 8) & 0x0F) | 0x80, size & 0xFF, 0xFF, 0x03]) + ppp

def ppp_frame(proto, code, ident, payload=b""):
    body = struct.pack(">HBBH", proto, code, ident, 4 + len(payload)) + payload
    return body

def udp_reply(vip, srv_ip, cli_port, srv_port, payload=b""):
    # IP packet from "server" (dst ip = cli_ip) to client (vip), UDP.
    # The source is the target the client sent to, as a real NAT would.
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    ip = bytearray(20)
    ip[0] = 0x45; ip[2:4] = struct.pack(">H", ip_len); ip[8] = 64; ip[9] = 17
    ip[12:16] = socket.inet_aton(str(srv_ip)); ip[16:20] = socket.inet_aton(str(vip))
    ip[10:12] = struct.pack(">H", csum(bytes(ip)))
    udp = bytearray(8)
    udp[0:2] = struct.pack(">H", srv_port); udp[2:4] = struct.pack(">H", cli_port)
    udp[4:6] = struct.pack(">H", udp_len)
    pseudo = socket.inet_aton(str(srv_ip)) + socket.inet_aton(str(vip)) + bytes([0, 17]) + struct.pack(">H", udp_len)
    udp[6:8] = struct.pack(">H", csum(pseudo + bytes(udp) + payload))
    return sstp_data(b"\x00\x21" + bytes(ip) + bytes(udp) + payload)

def tcp_reply(vip, srv_ip, cli_port, srv_port, srv_seq, cli_seq, flags, payload=b""):
    # IP packet from "server" (dst ip = cli_ip) to client (vip)
    tcp_len = 20 + len(payload)
    ip_len = 20 + tcp_len
    ip = bytearray(20)
    ip[0] = 0x45; ip[2:4] = struct.pack(">H", ip_len); ip[8] = 64; ip[9] = 6
    ip[12:16] = socket.inet_aton(str(srv_ip)); ip[16:20] = socket.inet_aton(str(vip))
    ip[10:12] = struct.pack(">H", csum(bytes(ip)))
    tcp = bytearray(20)
    tcp[0:2] = struct.pack(">H", srv_port); tcp[2:4] = struct.pack(">H", cli_port)
    tcp[4:8] = struct.pack(">I", srv_seq); tcp[8:12] = struct.pack(">I", cli_seq)
    tcp[12] = 0x50; tcp[13] = flags; tcp[14:16] = struct.pack(">H", 65535)
    pseudo = socket.inet_aton(str(srv_ip)) + socket.inet_aton(str(vip)) + bytes([0, 6]) + struct.pack(">H", tcp_len)
    tcp[16:18] = struct.pack(">H", csum(pseudo + bytes(tcp) + payload))
    return sstp_data(b"\x00\x21" + bytes(ip) + bytes(tcp) + payload)

class Buf:
    def __init__(self, s): self.s = s; self.b = b""
    def read_exact(self, n):
        while len(self.b) < n:
            d = self.s.recv(4096)
            if not d: raise EOFError("closed")
            self.b += d
        r, self.b = self.b[:n], self.b[n:]
        return r
    def read_until(self, pat):
        while pat not in self.b:
            d = self.s.recv(4096)
            if not d: raise EOFError("closed")
            self.b += d
        i = self.b.index(pat) + len(pat)
        r, self.b = self.b[:i], self.b[i:]
        return r
    def read_packet(self):
        hd = self.read_exact(4)
        total = struct.unpack(">H", hd[2:4])[0] & 0x0FFF
        body = self.read_exact(total - 4)
        return (hd[1] & 1) == 1, body

def handle(conn):
    buf = Buf(conn)
    req = buf.read_until(b"\r\n\r\n")
    assert b"SSTP_DUPLEX_POST" in req, req[:100]
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
    vip = "10.0.0.2"
    conns = {}  # (cli_ip, cli_port) -> {"srv_seq": int, "est": bool}
    while True:
        try: ctrl, body = buf.read_packet()
        except EOFError: return
        if ctrl:
            print("  [mock] ctrl pkt", flush=True)
            continue
        if body[:2] != b"\xff\x03": continue
        ppp = body[2:]
        proto = struct.unpack(">H", ppp[:2])[0]
        print(f"  [mock] data proto={hex(proto)} code={ppp[2] if len(ppp)>2 else '?'} len={len(ppp)}", flush=True)
        if proto == 0xC021:  # LCP
            code, ident = ppp[2], ppp[3]
            if code == 1:
                ack = bytearray(ppp); ack[2] = 2
                conn.sendall(sstp_data(bytes(ack)))
                # own Configure-Request (MRU 1500)
                own = ppp_frame(0xC021, 1, 99, bytes([1, 4, 5, 220]))
                conn.sendall(sstp_data(own))
            # code 2 (Ack to our Req): ignore
        elif proto == 0xC023:  # PAP
            code, ident = ppp[2], ppp[3]
            if code == 1:
                conn.sendall(sstp_data(ppp_frame(0xC023, 2, ident, b"OK")))
        elif proto == 0x8021:  # IPCP
            code, ident = ppp[2], ppp[3]
            if code == 1:
                # Ack offering 10.0.0.2
                opt = bytes([3, 6]) + socket.inet_aton(vip)
                conn.sendall(sstp_data(ppp_frame(0x8021, 2, ident, opt)))
        elif proto == 0x0021:  # IPv4
            ip = ppp[2:]
            ihl = (ip[0] & 0x0F) * 4
            iproto = ip[9]
            src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
            sport, dport = struct.unpack(">HH", ip[ihl:ihl+4])
            if iproto == 17:  # UDP: stateless echo (proves the tunnel carries UDP)
                udp_len = struct.unpack(">H", ip[ihl+4:ihl+6])[0]
                end = min(ihl + udp_len, len(ip))
                payload = ip[ihl+8:end]
                print(f"  [mock] UDP {src}:{sport} -> {dst}:{dport} paylen={len(payload)}", flush=True)
                conn.sendall(udp_reply(vip, dst, sport, dport, payload))
                continue
            seq, ack = struct.unpack(">II", ip[ihl+4:ihl+12])
            flags = ip[ihl+13]
            doff = (ip[ihl+12] >> 4) * 4
            payload = ip[ihl+doff:struct.unpack(">H", ip[2:4])[0]]
            key = (src, sport)
            st = conns.setdefault(key, {"srv_seq": 5000, "est": False, "echo": False})
            print(f"  [mock] TCP {src}:{sport} -> {dst}:{dport} flags={hex(flags)} seq={seq} paylen={len(payload)}", flush=True)
            if flags & 0x02:  # SYN
                conn.sendall(tcp_reply(vip, dst, sport, dport, st["srv_seq"], seq+1, 0x12))
                st["srv_seq"] += 1
            elif flags & 0x10 and payload:
                # data: ACK + a reply. Normally the canned 204, but a
                # stream that starts with b"ECHO:" switches this
                # connection to echo mode: the payload (minus the
                # marker) comes back byte-for-byte, so a test can prove
                # a relay passes binary data through unmodified (a
                # canned 204 would not catch mangling). Later segments
                # of the same stream echo too, in case the sender's
                # bytes were split across packets.
                conn.sendall(tcp_reply(vip, dst, sport, dport, st["srv_seq"], seq+len(payload), 0x10))
                if payload.startswith(b"ECHO:"):
                    st["echo"] = True
                    resp = payload[5:]
                elif st["echo"]:
                    resp = payload
                else:
                    resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                conn.sendall(tcp_reply(vip, dst, sport, dport, st["srv_seq"], seq+len(payload), 0x18, resp))
                st["srv_seq"] += len(resp)
                st["est"] = True
            elif flags & 0x01:  # FIN
                conn.sendall(tcp_reply(vip, dst, sport, dport, st["srv_seq"], seq+1, 0x10))

def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/mock_sstp_cert.pem", "/tmp/mock_sstp_key.pem")
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 8443)); ls.listen(5)
    print("mock SSTP listening on 127.0.0.1:8443", flush=True)
    while True:
        c, _ = ls.accept()
        try:
            conn = ctx.wrap_socket(c, server_side=True)
        except Exception as e:
            print("tls accept failed:", e, flush=True); continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
