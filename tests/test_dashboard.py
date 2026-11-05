import base64
import re
import threading
import requests
from src.dashboard import make_dashboard
from src.dataset_manager import DatasetManager, Record
from src.pir_server import PIRServer
from src.client_proxy import ClientProxy
from src.transport import LocalTransport


def test_dashboard_private_client_and_cache():
    ds = DatasetManager([Record('one.example', '1.2.3.4'), Record('two.example', '5.6.7.8')], page_size=2)
    server = PIRServer(ds)
    client = ClientProxy(LocalTransport(server))
    httpd = make_dashboard(client, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{httpd.server_port}'
    try:
        html = requests.get(url + '/').text
        assert 'Private lookup' in html
        token = re.search("const token='([^']+)'", html).group(1)
        headers = {'X-Dashboard-Token': token}
        initial = requests.get(url + '/api/state').json()
        assert all(r['ip'] is None for r in initial['pages'][0]['records'])
        assert requests.post(url+'/api/query', json={'domain':'one.example'}).status_code == 403
        assert requests.get(url+'/api/state', headers={'Host':'evil.example'}).status_code == 403
        first = requests.post(url+'/api/query', json={'domain':'one.example'}, headers=headers).json()
        assert first['history'][0]['ip'] == '1.2.3.4'
        assert not first['history'][0]['cache_hit']
        assert first['history'][0]['stages']['encrypt_ms'] > 0
        assert server.evaluations == 1
        trace = first['history'][0]
        for kind in ('query', 'response'):
            wire = requests.post(url+'/api/wire', json={'kind':kind,'wire_id':trace['wire_id']}, headers=headers).json()
            decoded = base64.b64decode(wire['value'], validate=True)
            assert decoded == client.last_wire[kind]
            assert len(decoded) == trace[kind+'_bytes']
            assert wire['value'].startswith(trace[kind+'_base64_preview'])
        assert requests.post(url+'/api/wire', json={'kind':'query','wire_id':trace['wire_id']}).status_code == 403
        second = requests.post(url+'/api/query', json={'domain':'two.example'}, headers=headers).json()
        assert second['history'][0]['cache_hit']
        assert second['history'][0]['query_bytes'] == 0
        assert 'wire_id' not in second['history'][0]
        assert client.last_wire is None
        assert requests.post(url+'/api/wire', json={'kind':'query','wire_id':trace['wire_id']}, headers=headers).status_code == 409
        assert server.evaluations == 1
        assert requests.post(url+'/api/query', json={'domain':'absent.example'}, headers=headers).status_code == 404
        cleared = requests.post(url+'/api/cache/clear', json={}, headers=headers).json()
        assert cleared['metrics']['cached_pages'] == 0
        assert all(r['ip'] is None for r in cleared['pages'][0]['records'])
        resized = requests.post(url+'/api/partition', json={'page_size':1}, headers=headers).json()
        assert resized['capacity'] == 1
        assert resized['page_size'] == 1
        assert len(resized['pages']) == 2
        assert resized['history'] == []
        assert resized['metrics']['queries'] == 0
        assert resized['metrics']['cached_pages'] == 0
        assert all(not r['cached'] and r['ip'] is None for p in resized['pages'] for r in p['records'])
        assert requests.post(url+'/api/partition', json={'page_size':0}, headers=headers).status_code == 400
        assert requests.post(url+'/api/partition', json={'page_size':2}).status_code == 403
        fetched = requests.post(url+'/api/query', json={'domain':'two.example'}, headers=headers).json()
        assert fetched['history'][0]['ip'] == '5.6.7.8'
        assert not fetched['history'][0]['cache_hit']
        assert fetched['history'][0]['response_bytes'] == 524288
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()
