# Architecture and research boundaries

## Data and retrieval

Let N be records, S records per page, and M = ceil(N/S) pages. Sort normalized
domains, then use MurmurHash3 x86_32 with a shared seed for the starting page.
Resolve full pages with deterministic page-level linear probing. Pad the final
matrix to M x S with zero IPv4 integers. Store IPv4 as an unsigned 32-bit integer.
The BFV plaintext modulus 4295049217 exceeds every IPv4 value and is compatible
with batching for polynomial degree 8192. Decryption returns balanced signed
integers; reduce modulo the plaintext modulus to recover unsigned values.

The client downloads a versioned public manifest containing domain-to-page/offset
mapping, TTLs, and acquisition time. It contains no IP answers. This explicitly
solves collision mapping. Manifest distribution is an up-front bandwidth/storage
cost and reveals the supported domain universe, but not a client's selected name.
A snapshot digest binds both manifest and answer matrix. A version mismatch
rejects a query; cached answers have TTLs bound to the original snapshot epoch.

The client creates a BFV encrypted one-hot vector of length M. The server uses
only the public context and rotation keys, and evaluates one encrypted/plaintext
dot product for each of S columns. The client decrypts S scalar results and maps
them back to domains via the manifest, then inserts the complete page atomically.
Each scalar ciphertext has a 512 KiB fixed frame; a query is one frame and a
response has S frames. Queries for all indices have the same framed size.

## Security statement

The intended adversary is an honest-but-curious PIR server that follows the
protocol. Query privacy relies on the computational security of BFV and its
underlying hardness assumptions. It is not a zero-knowledge proof and does not
provide information-theoretic privacy. Unit tests check isolation, framing and
functional invariants; they do not prove cryptographic security.

The server sees client IP addresses, public parameters, snapshot, request times,
session continuity, and request counts. Cache hits suppress network requests,
which changes observable traffic. Fixed payload sizes do not conceal timing,
connection patterns, or browsing side channels. TLS protects transit and
endpoint authentication; PIR hides the requested index from the server.

The client accepts replies only through normal BFV decryption and structural
validation. BFV is malleable and this design does not authenticate DNS data from
a malicious server. There is no DNSSEC validation, verifiable PIR, padding with
cover traffic, malicious-query validity proof, or private set membership. A
malicious client is not restricted to one-hot selectors. Remote deployment needs
resource admission controls and process isolation for hostile serialized inputs.
The basic threaded Python HTTP service is a research/demo service.

## Scope and performance

This is an IPv4 snapshot implementation. It does not follow CNAME chains, return
multiple addresses, resolve AAAA, refresh records in place, or perform recursion.
Dataset preparation follows upstream resolution to obtain an A answer; it does
not preserve the original DNS chain. Short upstream TTLs can require frequent
snapshot rebuilding and public manifest redistribution.

Grouping reduces selector length from N to M but increases response width from
one record to S. This implementation does S dot products over M rows; total work
does not automatically fall by S. BFV batching, rotation counts, large response
sizes, and cache locality determine actual performance. Random hashing also does
not guarantee that related browsing domains share a page. A 90% cache hit rate or
100x server speedup must be measured for a specified trace and cache budget.

The core uses TenSEAL BFV over Microsoft SEAL. References:
- https://github.com/OpenMined/TenSEAL
- https://github.com/microsoft/SEAL

## Module responsibilities

- dataset_manager: parsing, normalization, MurmurHash3, deterministic pages, manifest
- crypto_engine: client-only secret context, encrypted selector, framing, decryption
- pir_server: public context validation and universal column evaluation
- transport: local adapter and versioned HTTP(S) sessions
- client_proxy: lookup lifecycle, TTL enforcement, metrics, cache population
- lru_cache: atomic page eviction and resizing
- dns_proxy: loopback UDP and TCP IN/A frontend
- main.py: demo, server, query, shell and proxy commands
- benchmarks: flat/page comparisons with recorded seed and environment
