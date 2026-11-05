# Initial measured results

Measured on this workspace's Apple Silicon macOS host with Python 3.12.14 and
TenSEAL 0.3.18. These are small synthetic experiments, not internet-scale results.

Command:

```sh
python -m benchmarks.benchmark --records 64 --requests 30 --page-sizes 1 8
```

| Metric | Flat (1 record/page) | Paged (8 records/page) |
| --- | ---: | ---: |
| Pages | 64 | 8 |
| Median cold lookup | 12.73 ms | 51.03 ms |
| Median repeated warm lookup | 0.00137 ms | 0.00137 ms |
| Seeded 30-request trace cache hit rate | 40.0% | 63.3% |
| Mean trace lookup | 7.47 ms | 18.58 ms |
| Trace query upload | 9 MiB | 5.5 MiB |
| Trace response download | 9 MiB | 44 MiB |
| Public context upload (once/client) | about 50.15 MiB | about 50.15 MiB |

Context generation/registration took about 0.27–0.31 seconds in the in-process
adapter. These timings exclude network round trips, TLS overhead, and disk-based
snapshot preparation. The large rotation-key upload is a substantial setup cost.
The trace has only 30 requests; this is a smoke benchmark, not a statistical study.

This experiment does not support an automatic server speedup from page grouping.
Paging improves hit rate at a fixed four-page cache budget, which stores more
records for larger pages, but incurs additional output-column evaluations and
larger responses. A fair cache-memory comparison also needs fixed-record budgets.

For a final course evaluation, sweep dataset size and page size, hold cache bytes
or record capacity fixed, repeat seeds, record CPU/memory, measure LAN/WAN
transport separately, and use genuine browsing traces where permitted. Compare
identical traces and state all supported record types and freshness assumptions.

## Report-sized smoke check

Also executed successfully:

```sh
python -m benchmarks.benchmark --records 10000 --requests 5 --page-sizes 400 --output output/benchmark-10000.json
```

This constructs the report's 25 pages of 400 records and performs real BFV
lookups. Median cold latency was **5450.22 ms**, repeated warm median was
**0.00138 ms**, and the short five-request seeded trace had no cache hits.
Each padded response is **200 MiB** (400 scalar ciphertext frames). The five
trace requests downloaded 1000 MiB. Setup uploaded about 50.15 MiB once.
These results establish functional execution at that size; they do not match
the contribution report's unverified 1.4-second timing or 90% hit rate.
Efficient packed retrieval is a significant future optimization, not a property
of this straightforward column-wise dot-product implementation.
