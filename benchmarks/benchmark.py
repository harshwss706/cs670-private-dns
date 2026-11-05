"""Measured flat/page comparisons; run from repository root with -m."""
import argparse
import json
import platform
import random
import statistics
import time
from pathlib import Path
from src.client_proxy import ClientProxy
from src.dataset_manager import DatasetManager, Record
from src.pir_server import PIRServer
from src.transport import LocalTransport


def run(records, page_size, requests, seed):
    rng = random.Random(seed)
    ds = DatasetManager(records, page_size=page_size)
    server = PIRServer(ds)
    start = time.perf_counter()
    client = ClientProxy(LocalTransport(server), cache_pages=4)
    setup_s = time.perf_counter() - start
    setup_bytes = client.transport.sent
    domains = [r.domain for r in records]
    cold = []
    client.cache.resize(0)
    for domain in domains[:min(5, len(domains))]:
        client.query(domain)
        cold.append(client.metrics['latency_ms'])
    client.cache.resize(4)
    client.query(domains[0])
    warm = []
    for _ in range(100):
        client.query(domains[0])
        warm.append(client.metrics['latency_ms'])
    client.cache.pages.clear()
    before = client.stats()
    trace = []
    for _ in range(requests):
        domain = rng.choices(domains, weights=[1/(i+1)**1.1 for i in range(len(domains))])[0]
        client.query(domain)
        trace.append(client.metrics['latency_ms'])
    after = client.stats()
    return {'page_size': page_size, 'pages': len(ds.pages), 'setup_s': setup_s,
            'setup_upload_bytes': setup_bytes,
            'cold_median_ms': statistics.median(cold), 'warm_median_ms': statistics.median(warm),
            'trace_mean_ms': statistics.mean(trace),
            'trace_hit_rate': (after['hits']-before['hits'])/requests,
            'trace_upload_bytes': after['sent_bytes']-before['sent_bytes'],
            'trace_download_bytes': after['received_bytes']-before['received_bytes']}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--records', type=int, default=64)
    p.add_argument('--requests', type=int, default=30)
    p.add_argument('--page-sizes', type=int, nargs='+', default=[1, 8])
    p.add_argument('--output', default='output/benchmark.json')
    args = p.parse_args()
    if args.records < 1 or args.requests < 1:
        p.error('records and requests must be positive')
    records = [Record(f'site{i:05}.example', f'192.0.2.{i%254+1}', 86400) for i in range(args.records)]
    results = {'platform': platform.platform(), 'python': platform.python_version(),
               'records': args.records, 'requests': args.requests, 'seed': 42, 'results': []}
    for size in args.page_sizes:
        result = run(records, size, args.requests, 42)
        results['results'].append(result)
        print(json.dumps(result), flush=True)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
