# Page-partitioned BFV PIR DNS

An executable CS670 research prototype: deterministic page construction, real
TenSEAL BFV queries, public-key-only server evaluation, versioned HTTP(S), page LRU
caching, and a loopback UDP/TCP DNS frontend. No fake encryption backend is used.

## Setup and first run

Python 3.12 is recommended. From the repository root:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py demo
```

The demo uses 64 synthetic `.example` domains and documentation-range IPs.
It prints a cold encrypted lookup followed by a warm local lookup, with timing
and application-payload byte counters. These IPs demonstrate correctness; they
do not point to real websites.

## Run separate server and client processes

Terminal 1:

```sh
source .venv/bin/activate
python main.py server --dataset data/demo.csv --page-size 8 --port 8080
```

Terminal 2:

```sh
source .venv/bin/activate
python main.py query site000.example
python main.py shell
```

The shell supports domains, `stats`, `pages`, `cached`, `sample`, `resize N`, and
`quit`. A long-lived client retains its key/context and cache. Each one-shot
`query` starts a new client, including public context upload.

## DNS integration

Keep the server running. In another terminal:

```sh
python main.py proxy --port 5353
```

Then query it from a third terminal:

```sh
dig @127.0.0.1 -p 5353 site000.example A
dig @127.0.0.1 -p 5353 site000.example A +tcp
```

Only IN/A records in the snapshot are supported. Unknown names and unsupported
record types return REFUSED; expired records and evaluation failures return
SERVFAIL. There is no public-resolver fallback, so an absent domain is not silently
sent in plaintext. This is a finite snapshot service, not a full recursive resolver.
The proxy does not change OS DNS settings and uses an unprivileged port.

## Real domain data

Use a Tranco `rank,domain` CSV or a text file containing one domain per line:

```sh
python scripts/prepare_dataset.py top-domains.csv --limit 1000 --output data/resolved.csv
python main.py server --dataset data/resolved.csv --page-size 25
```

Dataset preparation performs ordinary DNS queries on the server side; it is an
offline acquisition step. Failed or already-expired answers are excluded rather
than replaced with invented IPs. The current schema chooses one IPv4 answer per
domain. Keep the generated `.meta.json` sidecar: it anchors TTLs to acquisition.
Refresh the dataset and restart server and clients when the snapshot expires or
changes. Plain user CSVs use load time as the snapshot epoch; provide a sidecar
with `{"created_at": <unix timestamp>}` to preserve an existing acquisition epoch.

## HTTPS

Loopback HTTP is available for development. Remote URLs require HTTPS and remote
server binds require a certificate. Use a certificate whose SAN matches the host:

```sh
python main.py server --host 0.0.0.0 --cert server.crt --key server.key
python main.py query --server https://your-host:8080 --ca ca.crt site000.example
```

Certificate verification stays enabled. Each session has a public BFV context;
the server retains at most four sessions and evicts the least recently used.
An evicted client must restart to register again.

## Verification and experiments

```sh
python -m pytest -q
python -m benchmarks.benchmark --records 64 --requests 30 --page-sizes 1 8
```

The benchmark writes `output/benchmark.json`. Page size 1 is a flat BFV baseline.
It separately measures context setup, cold lookups, repeated warm lookups, a
seeded Zipf workload, and uploaded/downloaded application payloads. It does not
include TLS/TCP framing in byte counters. Compare multiple page sizes and dataset
sizes before drawing scaling conclusions. The benchmark keeps four cache pages,
so larger pages also increase cache capacity in records; account for that in any
paper comparison. It does not reproduce PDNS's optimized implementation.

See [the design](docs/DESIGN.md) for protocol details, assumptions, and limitations.

For the exact dependency versions validated on this machine, install
`requirements-lock.txt` instead of the ranged requirements file. Measured smoke
results and their limitations are recorded in [experiments](docs/EXPERIMENTS.md).
The BFV API follows the [official TenSEAL tutorial](https://github.com/OpenMined/TenSEAL/blob/main/tutorials/Tutorial%200%20-%20Getting%20Started.ipynb).

## Presentation dashboard

Keep the PIR server running on port 8081. In a second terminal:

```sh
source .venv/bin/activate
python main.py dashboard --server http://127.0.0.1:8081 --port 8090
```

Open **http://127.0.0.1:8090**. Port 8081 is the PIR API; port 8090 is the local
client dashboard. Use **Run guided demo** to clear the cache, retrieve a page,
repeat the same query, then query a prefetched neighbor. The page explorer shows
IPs only after decryption. Click any domain for another live lookup. The dashboard cache holds exactly one page. Change **Page / cache size** to
change records per page; the server repartitions the same records, the client
refreshes its mapping, and cached pages, lookup history, and ciphertext viewers
are cleared. All domain cards and filters then use the rebuilt partition.
Querying a different page evicts the previous cached page. Export the session
as JSON for your report.

Encryption, HTTP round trip including server evaluation, decryption, and total
resolution timings are measured by the Python client. The journey animation
replays the completed operation for explanation; it is not live server tracing.
The dashboard and shell/proxy are independent clients with separate caches.
The guided demo clears cache entries but retains cumulative metrics/history.

The dashboard binds only to loopback. It holds the private key in its local
Python process and sends ciphertext to the separate PIR server. It does not send
the domain to the PIR API. Browser inputs and history are visible locally, so
use it on a trusted machine. The dashboard is not intended to be hosted on the
remote PIR server.

### Encrypted payload viewer

On a dashboard cache miss, **Encrypted query & response** shows the first 512
Base64 characters of each actual wire payload. Base64 is a text representation
of the already-encrypted BFV data, not an additional encryption scheme. The
payload includes serialization headers, framing, and fixed-size padding.
**Copy full query/response** and **Download .txt** retrieve the complete strings.
Only the latest successful cold transaction is kept in memory for export;
cache hits clear it. History retains small previews, not full payloads. Capture
is enabled only for the dashboard client and does not include secret keys.

### Live page-size changes

The dashboard size control means **records per page**, not a number of cached
pages. For 64 records, size 8 gives 8 pages, size 16 gives 4 pages, and size 25
gives 3 pages (some pages may be partially filled). All mappings are rebuilt
using the original hash seed. IPs, record count, and original TTL deadlines stay
unchanged. Changing layout never renews an expired DNS answer.

The cache is emptied before rebuilding; the updated partition becomes visible
only after the server and client mapping are ready. Rebuilds and PIR evaluations
are serialized. The versioned server rejects old selectors. This control is
available only against a loopback-bound demo server with a registered session.
Other independently running shell/proxy clients should be restarted after a
partition change to load the new mapping. Lookup metrics reset per partition;
transport byte totals remain cumulative for the dashboard session.
