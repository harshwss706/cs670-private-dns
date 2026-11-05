"""Resolve a ranked CSV/domain list to a real IPv4 snapshot. Run before serving."""
import argparse
import concurrent.futures
import csv
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns.resolver
from src.dataset_manager import normalize


def resolve(domain):
    try:
        answer = dns.resolver.resolve(domain, 'A', lifetime=5)
        return domain, str(answer[0]), max(1, min(604800, answer.rrset.ttl))
    except Exception:
        return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', help='Tranco rank,domain CSV or one domain per line')
    p.add_argument('--output', default='data/resolved.csv')
    p.add_argument('--limit', type=int, default=1000)
    p.add_argument('--workers', type=int, default=8)
    args = p.parse_args()
    if args.limit < 1 or not 1 <= args.workers <= 32:
        p.error('positive limit and 1..32 workers required')
    domains = []
    with open(args.input) as f:
        for row in csv.reader(f):
            if not row:
                continue
            try:
                domain = normalize(row[1] if len(row)>1 and row[0].isdigit() else row[0])
            except ValueError:
                continue
            if domain in ('domain', 'rank') or domain in domains:
                continue
            domains.append(domain)
            if len(domains) == args.limit:
                break
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(resolve, domains))
    # Deduct acquisition time conservatively so an old answer is never renewed.
    elapsed = int(time.time() - started) + 1
    rows = [(d, ip, ttl-elapsed) for result in results if result for d, ip, ttl in [result] if ttl>elapsed]
    if not rows:
        raise SystemExit('No unexpired A records resolved; output was not written.')
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['domain','ip','ttl'])
        w.writerows(rows)
    # Sidecar anchors TTLs to acquisition rather than subsequent server restarts.
    path.with_suffix(path.suffix + '.meta.json').write_text(
        __import__('json').dumps({'created_at': time.time(), 'source': str(args.input)}))
    print(f'Wrote {len(rows)}/{len(domains)} domains to {path}; refresh after TTL expiry.')


if __name__ == '__main__':
    main()
