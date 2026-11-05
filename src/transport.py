"""Versioned HTTP transport. TLS is required except for loopback development."""
import json
import secrets
import ssl
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import requests
from .crypto_engine import FRAME_BYTES


class SnapshotChanged(RuntimeError):
    pass


class LocalTransport:
    def __init__(self, server):
        self.server = server
        self.context = None
        self.sent = self.received = 0

    def manifest(self):
        return self.server.dataset.manifest

    def register(self, blob):
        self.context = self.server.load_context(blob)
        self.sent += len(blob)

    def query(self, blob, version):
        with self.server.lock:
            if version != self.manifest()['version']:
                raise SnapshotChanged('snapshot changed; restart client')
            response = self.server.evaluate(blob, self.context)
        self.sent += len(blob)
        self.received += len(response)
        return response

    def repartition(self, page_size, version):
        return self.server.repartition(page_size, version)


class HTTPTransport:
    def __init__(self, url, ca=True):
        parts = urlparse(url)
        if parts.scheme != 'https' and not (
            parts.scheme == 'http' and parts.hostname in ('127.0.0.1', 'localhost', '::1')
        ):
            raise ValueError('HTTPS required for remote servers')
        self.url = url.rstrip('/')
        self.ca = ca
        self.session = requests.Session()
        self.sent = self.received = 0
        self.token = None

    def manifest(self):
        response = self.session.get(self.url + '/manifest', verify=self.ca, timeout=30)
        response.raise_for_status()
        return response.json()

    def register(self, blob):
        response = self.session.post(self.url + '/session', data=blob, verify=self.ca, timeout=120)
        response.raise_for_status()
        self.sent += len(blob)
        self.token = response.json()['session']

    def query(self, blob, version):
        response = self.session.post(self.url + '/query', data=blob,
            headers={'X-PIR-Session': self.token, 'X-PIR-Version': version},
            verify=self.ca, timeout=180)
        if response.status_code == 409:
            raise SnapshotChanged('snapshot changed; restart client')
        response.raise_for_status()
        self.sent += len(blob)
        self.received += len(response.content)
        return response.content

    def repartition(self, page_size, version):
        response = self.session.post(self.url + '/partition', json={'page_size': page_size},
            headers={'X-PIR-Session': self.token, 'X-PIR-Version': version},
            verify=self.ca, timeout=180)
        if response.status_code == 409:
            raise SnapshotChanged('snapshot changed; refresh before repartitioning')
        response.raise_for_status()
        return response.json()


def make_http_server(server, host='127.0.0.1', port=8080, cert=None, key=None):
    if host not in ('127.0.0.1', 'localhost', '::1') and not cert:
        raise ValueError('non-loopback bind requires TLS certificate and key')
    sessions = OrderedDict()
    lock = server.lock

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body, content_type='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != '/manifest':
                return self.reply(404, b'{}')
            with lock:
                self.reply(200, json.dumps(server.dataset.manifest).encode())

        def do_POST(self):
            self.connection.settimeout(120)
            try:
                limit = 64 * 1024 * 1024 if self.path == '/session' else FRAME_BYTES
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= limit:
                    return self.reply(413, b'{"error":"body too large or empty"}')
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError('truncated request')
                # Serialize evaluation and session loading to bound HE memory usage.
                with lock:
                    if self.path == '/session':
                        context = server.load_context(body)
                        token = secrets.token_urlsafe(32)
                        sessions[token] = context
                        while len(sessions) > 4:
                            sessions.popitem(last=False)
                        return self.reply(200, json.dumps({'session': token}).encode())
                    if self.path not in ('/query', '/partition'):
                        return self.reply(404, b'{}')
                    if self.headers.get('X-PIR-Version') != server.dataset.manifest['version']:
                        return self.reply(409, b'{"error":"snapshot mismatch"}')
                    token = self.headers.get('X-PIR-Session')
                    if token not in sessions:
                        return self.reply(401, b'{"error":"session expired; restart client"}')
                    sessions.move_to_end(token)
                    if self.path == '/partition':
                        if host not in ('127.0.0.1', 'localhost', '::1') or self.client_address[0] not in ('127.0.0.1', '::1'):
                            return self.reply(403, b'{"error":"repartition is local-demo only"}')
                        manifest = server.repartition(json.loads(body)['page_size'],
                            self.headers.get('X-PIR-Version'))
                        return self.reply(200, json.dumps(manifest).encode())
                    result = server.evaluate(body, sessions[token])
                self.reply(200, result, 'application/octet-stream')
            except Exception:
                self.reply(400, b'{"error":"invalid PIR request"}')

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd
