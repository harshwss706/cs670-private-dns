"""Loopback UDP and TCP DNS frontend; supported records are IN/A only."""
import socketserver
import struct
import threading
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from .client_proxy import UnknownDomain


def answer(wire, client, tcp=False):
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    if query.opcode() != 0 or len(query.question) != 1:
        response.set_rcode(dns.rcode.FORMERR)
    else:
        question = query.question[0]
        if question.rdclass != dns.rdataclass.IN or question.rdtype != dns.rdatatype.A:
            response.set_rcode(dns.rcode.REFUSED)
        else:
            try:
                ip, ttl = client.query(str(question.name))
                response.answer.append(dns.rrset.from_text(question.name, ttl, 'IN', 'A', ip))
            except UnknownDomain:
                # A finite snapshot cannot prove global DNS nonexistence.
                response.set_rcode(dns.rcode.REFUSED)
            except Exception:
                response.set_rcode(dns.rcode.SERVFAIL)
    return response.to_wire(max_size=65535 if tcp else 512, prefer_truncation=True)


def serve_dns(client, host='127.0.0.1', port=5353):
    if host != '127.0.0.1':
        raise ValueError('DNS frontend must bind to loopback')

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request[1].sendto(answer(self.request[0], client), self.client_address)
            except Exception:
                pass  # Ignore malformed datagrams.

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(180)
            def receive(n):
                data = b''
                while len(data) < n:
                    part = self.request.recv(n - len(data))
                    if not part:
                        raise EOFError
                    data += part
                return data
            try:
                while True:
                    size, = struct.unpack('!H', receive(2))
                    wire = answer(receive(size), client, tcp=True)
                    self.request.sendall(struct.pack('!H', len(wire)) + wire)
            except (EOFError, OSError, ValueError):
                pass

    class UDPServer(socketserver.ThreadingUDPServer):
        allow_reuse_address = True
        daemon_threads = True

    class TCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with UDPServer((host, port), UDP) as udp, TCPServer((host, port), TCP) as tcp:
        thread = threading.Thread(target=tcp.serve_forever, daemon=True)
        thread.start()
        print(f'DNS proxy on {host}:{port} (UDP/TCP), IN/A snapshot records only', flush=True)
        try:
            udp.serve_forever()
        finally:
            tcp.shutdown()
