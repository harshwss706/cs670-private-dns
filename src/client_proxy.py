import base64
import ipaddress
import threading
import time
import uuid
from .crypto_engine import CryptoEngine
from .dataset_manager import normalize
from .lru_cache import PageCache


class UnknownDomain(LookupError):
    pass


class ExpiredRecord(RuntimeError):
    pass


class ClientProxy:
    def __init__(self, transport, cache_pages=16):
        self.transport = transport
        self.manifest = transport.manifest()
        self.index = {r['domain']: (i, j) for i, page in enumerate(self.manifest['pages'])
                      for j, r in enumerate(page)}
        self.crypto = CryptoEngine()
        transport.register(self.crypto.public_context())
        self.cache = PageCache(cache_pages)
        self.lock = threading.RLock()
        self.metrics = {'queries': 0, 'hits': 0, 'misses': 0, 'latency_ms': 0.0}
        self.last_lookup = None
        self.capture_wire = False
        self.last_wire = None

    def query(self, domain):
        start = time.perf_counter()
        domain = normalize(domain)
        with self.lock:
            self.last_wire = None
            if domain not in self.index:
                raise UnknownDomain(domain)
            page, offset = self.index[domain]
            record = self.manifest['pages'][page][offset]
            expiry = self.manifest['created_at'] + record['ttl']
            if expiry <= time.time():
                raise ExpiredRecord('snapshot record expired; refresh dataset and restart server/client')
            result = self.cache.get(page, domain)
            trace = {'domain': domain, 'page': page, 'cache_hit': bool(result),
                     'query_bytes': 0, 'response_bytes': 0, 'stages': {}}
            self.metrics['queries'] += 1
            if result:
                self.metrics['hits'] += 1
            else:
                self.metrics['misses'] += 1
                stage_start = time.perf_counter()
                request = self.crypto.query(page, len(self.manifest['pages']))
                trace['stages']['encrypt_ms'] = (time.perf_counter() - stage_start) * 1000
                trace['ciphertext_preview'] = request[4:36].hex()
                trace['query_bytes'] = len(request)
                stage_start = time.perf_counter()
                response = self.transport.query(request, self.manifest['version'])
                trace['stages']['round_trip_ms'] = (time.perf_counter() - stage_start) * 1000
                trace['response_bytes'] = len(response)
                stage_start = time.perf_counter()
                values = self.crypto.decrypt(response, self.manifest['page_size'])
                trace['stages']['decrypt_ms'] = (time.perf_counter() - stage_start) * 1000
                # Validate entire page before changing cache state.
                entries = {}
                for j, item in enumerate(self.manifest['pages'][page]):
                    entries[item['domain']] = (str(ipaddress.IPv4Address(values[j])),
                        self.manifest['created_at'] + item['ttl'])
                if expiry <= time.time():
                    raise ExpiredRecord('record expired during PIR evaluation')
                self.cache.put(page, entries)
                result = entries[domain][0], max(0, int(expiry - time.time()))
            self.metrics['latency_ms'] = (time.perf_counter() - start) * 1000
            trace.update(ip=result[0], ttl=result[1], latency_ms=self.metrics['latency_ms'])
            if self.capture_wire and not trace['cache_hit']:
                trace['wire_id'] = uuid.uuid4().hex
                trace['query_base64_preview'] = base64.b64encode(request[:384]).decode('ascii')
                trace['response_base64_preview'] = base64.b64encode(response[:384]).decode('ascii')
                self.last_wire = {'query': request, 'response': response}
            self.last_lookup = trace
            return result

    def stats(self):
        return dict(self.metrics, sent_bytes=self.transport.sent,
                    received_bytes=self.transport.received, cached_pages=len(self.cache.pages))

    def repartition(self, page_size):
        if type(page_size) is not int or not 1 <= page_size <= 1024:
            raise ValueError('page size must be an integer from 1 to 1024')
        with self.lock:
            # Old cached pages and wire payloads cannot survive a mapping change.
            self.cache.pages.clear()
            self.last_wire = self.last_lookup = None
            manifest = self.transport.repartition(page_size, self.manifest['version'])
            self.manifest = manifest
            self.index = {r['domain']: (i, j) for i, page in enumerate(manifest['pages'])
                          for j, r in enumerate(page)}
            self.cache.resize(1)
            self.metrics = {'queries': 0, 'hits': 0, 'misses': 0, 'latency_ms': 0.0}
