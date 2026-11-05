import threading
import pytest
from src.dataset_manager import DatasetManager, Record
from src.pir_server import PIRServer
from src.client_proxy import ClientProxy
from src.transport import LocalTransport, HTTPTransport, SnapshotChanged, make_http_server
from src.crypto_engine import FRAME_BYTES


@pytest.mark.parametrize('network', [False, True])
def test_repartition_preserves_records_rebuilds_mapping_and_invalidates_cache(network):
    records = [Record(f'd{i}.example', f'192.0.2.{i+1}', 3600) for i in range(10)]
    ds = DatasetManager(records, page_size=2, seed=42)
    server = PIRServer(ds)
    httpd = make_http_server(server, port=0) if network else None
    if httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
    transport = HTTPTransport(f'http://127.0.0.1:{httpd.server_port}') if network else LocalTransport(server)
    try:
        client = ClientProxy(transport, cache_pages=1)
        client.capture_wire = True
        assert client.query(records[0].domain)[0] == records[0].ip
        old_version = client.manifest['version']
        old_index = dict(client.index)
        old_request = client.crypto.query(0, len(ds.pages))
        client.repartition(4)
        assert client.cache.capacity == 1
        assert not client.cache.pages and client.last_wire is None and client.last_lookup is None
        assert client.metrics['queries'] == 0
        assert len(client.manifest['pages']) == 3
        assert [len(p) for p in client.manifest['pages']].count(4) == 2
        assert client.index != old_index
        assert client.manifest['created_at'] == ds.created_at
        assert server.dataset.seed == 42
        assert {r for p in server.dataset.pages for r in p} == set(records)
        with pytest.raises(SnapshotChanged):
            transport.query(old_request, old_version)
        with pytest.raises(SnapshotChanged):
            transport.repartition(2, old_version)
        for size in (4, 1, 6):
            if size != 4:
                client.repartition(size)
            for record in records:
                assert client.query(record.domain)[0] == record.ip
                assert len(client.cache.pages) == 1
            assert client.manifest['page_size'] == size
        client.cache.pages.clear()
        client.query(records[0].domain)
        assert client.last_lookup['response_bytes'] == 6 * FRAME_BYTES
        before = client.manifest
        for invalid in (0, -1, 1025, 2.5, True, '4'):
            with pytest.raises(ValueError):
                client.repartition(invalid)
            assert client.manifest is before
    finally:
        if httpd:
            httpd.shutdown()
            httpd.server_close()
            thread.join()
