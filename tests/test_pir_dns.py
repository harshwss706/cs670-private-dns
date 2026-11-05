import threading
import time
import pytest
import dns.message
import dns.rcode
import tenseal as ts
from src.dataset_manager import DatasetManager, Record, murmurhash3, normalize
from src.crypto_engine import CryptoEngine, FRAME_BYTES, pack, unpack
from src.pir_server import PIRServer
from src.transport import LocalTransport, HTTPTransport, make_http_server, SnapshotChanged
from src.client_proxy import ClientProxy, UnknownDomain, ExpiredRecord
from src.lru_cache import PageCache
from src.dns_proxy import answer


@pytest.fixture(scope='module')
def setup():
    records = [Record(f'site{i}.example', str(__import__('ipaddress').IPv4Address(i * 123456789 % 2**32)), 3600)
               for i in range(10)]
    ds = DatasetManager(records, page_size=3)
    server = PIRServer(ds)
    client = ClientProxy(LocalTransport(server), cache_pages=2)
    return ds, server, client


def test_hash_and_normalization():
    assert murmurhash3('') == 0
    assert murmurhash3('foo') == 4138058784
    assert murmurhash3('hello') == 613153351
    assert normalize('EXAMPLE.COM.') == 'example.com'
    with pytest.raises(ValueError):
        normalize('-bad.example')


def test_mapping(setup):
    ds, _, _ = setup
    reversed_ds = DatasetManager([r for p in reversed(ds.pages) for r in p], page_size=3, created_at=ds.created_at)
    assert ds.manifest == reversed_ds.manifest
    assert sum(map(len, ds.pages)) == 10
    assert all(len(p) <= 3 for p in ds.pages)
    assert all(len(row) == 3 for row in ds.matrix)
    with pytest.raises(ValueError):
        DatasetManager([Record('x.example', '1.1.1.1'), Record('X.example', '2.2.2.2')])


def test_all_pages_and_unsigned_ipv4(setup):
    ds, server, client = setup
    client.cache.resize(0)
    before = server.evaluations
    for page in ds.pages:
        for record in page:
            assert client.query(record.domain)[0] == record.ip
    assert server.evaluations - before == 10


def test_cache_prefetch(setup):
    ds, server, client = setup
    client.cache.resize(2)
    page = ds.pages[0]
    before = server.evaluations
    client.query(page[0].domain)
    client.query(page[1].domain)
    assert server.evaluations - before == 1
    with pytest.raises(UnknownDomain):
        client.query('unknown.example')


def test_public_context_and_randomization(setup):
    ds, server, client = setup
    context = server.load_context(client.crypto.public_context())
    assert not context.has_secret_key()
    with pytest.raises(ValueError):
        context.secret_key()
    a = client.crypto.query(0, len(ds.pages))
    b = client.crypto.query(0, len(ds.pages))
    c = client.crypto.query(1, len(ds.pages))
    assert len(a) == len(b) == len(c) == FRAME_BYTES
    assert a != b
    with pytest.raises(ValueError):
        server.load_context(client.crypto.context.serialize(save_secret_key=True))
    with pytest.raises(ValueError):
        server.evaluate(client.crypto.query(0, 1), context)
    with pytest.raises(ValueError):
        client.crypto.query(len(ds.pages), len(ds.pages))
    with pytest.raises(ValueError):
        unpack(a[:-1])


def test_lru_and_expiry():
    cache = PageCache(2)
    cache.put(0, {'a': ('1.1.1.1', time.time()+50)})
    cache.put(1, {'b': ('2.2.2.2', time.time()+50)})
    assert cache.get(0, 'a')
    cache.put(2, {'c': ('3.3.3.3', time.time()+50)})
    assert 1 not in cache.pages
    cache.resize(1)
    assert list(cache.pages) == [2]
    cache.put(3, {'x': ('0.0.0.0', time.time()-1)})
    assert cache.get(3, 'x') is None


def test_dns_wire_and_expired_snapshot(setup):
    ds, _, client = setup
    q = dns.message.make_query(ds.pages[0][0].domain, 'A')
    response = dns.message.from_wire(answer(q.to_wire(), client))
    assert response.id == q.id
    assert response.answer[0][0].address == ds.pages[0][0].ip
    for domain, typ in [('unknown.example', 'A'), ('site0.example', 'AAAA')]:
        q = dns.message.make_query(domain, typ)
        assert dns.message.from_wire(answer(q.to_wire(), client)).rcode() == dns.rcode.REFUSED
    original = client.manifest['created_at']
    try:
        client.manifest['created_at'] = 0
        with pytest.raises(ExpiredRecord):
            client.query(ds.pages[0][0].domain)
    finally:
        client.manifest['created_at'] = original


def test_http_end_to_end(setup):
    ds, server, local_client = setup
    httpd = make_http_server(server, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        transport = HTTPTransport(f'http://127.0.0.1:{httpd.server_port}')
        transport.register(local_client.crypto.public_context())
        manifest = transport.manifest()
        blob = local_client.crypto.query(0, len(ds.pages))
        response = transport.query(blob, manifest['version'])
        assert local_client.crypto.decrypt(response, ds.page_size) == ds.matrix[0]
        assert transport.sent > FRAME_BYTES
        assert transport.received == ds.page_size * FRAME_BYTES
        with pytest.raises(SnapshotChanged):
            transport.query(blob, 'wrong-version')
        bad = transport.session.post(transport.url + '/query', data=b'invalid',
            headers={'X-PIR-Session': transport.token, 'X-PIR-Version': manifest['version']})
        assert bad.status_code == 400
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_remote_requires_tls():
    with pytest.raises(ValueError):
        HTTPTransport('http://example.com')


def test_high_ipv4_and_padding(setup):
    _, _, client = setup
    ds = DatasetManager([Record('max.example', '255.255.255.255'),
                         Record('min.example', '0.0.0.0')], page_size=3)
    server = PIRServer(ds)
    context = server.load_context(client.crypto.public_context())
    result = server.evaluate(client.crypto.query(0, 1), context)
    assert client.crypto.decrypt(result, 3) == ds.matrix[0]


def test_separate_process_dns_pipeline():
    import socket
    import subprocess
    import sys
    import dns.query
    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]
    http_port, dns_port = free_port(), free_port()
    server = subprocess.Popen([sys.executable, 'main.py', 'server', '--port', str(http_port)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proxy = None
    def wait_ready(port, process):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(process.communicate())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        raise AssertionError('process startup timed out')
    try:
        wait_ready(http_port, server)
        proxy = subprocess.Popen([sys.executable, 'main.py', 'proxy', '--server',
            f'http://127.0.0.1:{http_port}', '--port', str(dns_port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wait_ready(dns_port, proxy)
        q = dns.message.make_query('site000.example', 'A')
        for send in (dns.query.udp, dns.query.tcp):
            reply = send(q, '127.0.0.1', port=dns_port, timeout=30)
            assert reply.answer[0][0].address == '192.0.2.1'
        unknown = dns.query.udp(dns.message.make_query('absent.example', 'A'),
                                '127.0.0.1', port=dns_port, timeout=30)
        assert unknown.rcode() == dns.rcode.REFUSED
    finally:
        for process in (proxy, server):
            if process:
                process.terminate()
                process.communicate(timeout=10)


def test_verified_https(setup, tmp_path):
    import subprocess
    _, server, client = setup
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    config = tmp_path / 'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                      '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n'
                      'basicConstraints=critical,CA:TRUE\n')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1', '-config', str(config)],
                   check=True, capture_output=True)
    httpd = make_http_server(server, port=0, cert=str(cert), key=str(key))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        transport = HTTPTransport(f'https://localhost:{httpd.server_port}', ca=str(cert))
        manifest = transport.manifest()
        transport.register(client.crypto.public_context())
        response = transport.query(client.crypto.query(0, len(server.dataset.pages)), manifest['version'])
        assert client.crypto.decrypt(response, server.dataset.page_size) == server.dataset.matrix[0]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()
