"""Loopback-only UI bridge. Domain input and private BFV key stay client-side."""
import base64
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from .client_proxy import UnknownDomain, ExpiredRecord


HTML = Path(__file__).resolve().parents[1] / 'dashboard' / 'index.html'


def make_dashboard(client, port=8090):
    client.capture_wire = True
    client.cache.resize(1)
    history = []
    token = secrets.token_urlsafe(32)

    def state():
        with client.lock:
            pages = []
            now = time.time()
            for i, records in enumerate(client.manifest['pages']):
                cached = client.cache.pages.get(i, {})
                entries = []
                for r in records:
                    entry = cached.get(r['domain'])
                    valid = bool(entry and entry[1] > now)
                    entries.append({'domain': r['domain'], 'cached': valid,
                                    'ip': entry[0] if valid else None})
                pages.append({'id': i, 'cached': any(e['cached'] for e in entries), 'records': entries})
            return {'metrics': client.stats(), 'pages': pages,
                    'history': list(history), 'capacity': client.cache.capacity,
                    'snapshot': client.manifest['version'][:12],
                    'server': getattr(client.transport, 'url', 'in-process'),
                    'records': len(client.index), 'page_size': client.manifest['page_size']}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, body, mime='application/json'):
            self.send_response(code)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def local_request(self):
            # Prevent DNS rebinding and cross-site mutations of a privileged local client.
            host = self.headers.get('Host', '')
            return host in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}')

        def do_GET(self):
            if not self.local_request():
                return self.reply(403, b'{}')
            if self.path == '/':
                return self.reply(200, HTML.read_bytes().replace(b'__CSRF_TOKEN__', token.encode()), 'text/html; charset=utf-8')
            if self.path == '/api/state':
                return self.reply(200, json.dumps(state()).encode())
            self.reply(404, b'{}')

        def do_POST(self):
            if not self.local_request() or self.headers.get('X-Dashboard-Token') != token:
                return self.reply(403, b'{"error":"invalid local request"}')
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 4096:
                    raise ValueError('invalid request size')
                body = json.loads(self.rfile.read(size))
                with client.lock:
                    if self.path == '/api/wire':
                        kind = body.get('kind')
                        if kind not in ('query', 'response'):
                            raise ValueError('kind must be query or response')
                        if (not client.last_wire or not client.last_lookup or
                                body.get('wire_id') != client.last_lookup.get('wire_id')):
                            return self.reply(409, b'{"error":"Payload is no longer available. Run a new cache-miss lookup."}')
                        wire = client.last_wire[kind]
                        return self.reply(200, json.dumps({'encoding': 'base64', 'bytes': len(wire),
                            'value': base64.b64encode(wire).decode('ascii')}).encode())
                    elif self.path == '/api/query':
                        client.query(body.get('domain', ''))
                        history.insert(0, dict(client.last_lookup))
                        del history[50:]
                    elif self.path == '/api/cache/clear':
                        client.cache.pages.clear()
                    elif self.path == '/api/partition':
                        client.repartition(body['page_size'])
                        history.clear()
                    else:
                        return self.reply(404, b'{}')
                    result = state()
                self.reply(200, json.dumps(result).encode())
            except UnknownDomain:
                self.reply(404, b'{"error":"Domain is outside this snapshot. Choose a domain from the page explorer."}')
            except ExpiredRecord as exc:
                self.reply(409, json.dumps({'error': str(exc)}).encode())
            except (ValueError, KeyError, TypeError) as exc:
                self.reply(400, json.dumps({'error': str(exc)}).encode())
            except Exception:
                self.reply(502, b'{"error":"PIR request failed. Check the server terminal. If the session expired, restart the dashboard."}')

    httpd = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    httpd.daemon_threads = True
    return httpd


def serve_dashboard(client, port=8090):
    with make_dashboard(client, port) as httpd:
        print(f'Dashboard: http://127.0.0.1:{httpd.server_port} (local client; keep this terminal open)', flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
