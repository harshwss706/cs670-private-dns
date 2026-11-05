import csv
import hashlib
import ipaddress
import json
import math
import time
from pathlib import Path
from dataclasses import dataclass


def normalize(domain):
    domain = domain.strip().rstrip('.').lower().encode('idna').decode('ascii')
    if not domain or len(domain) > 253:
        raise ValueError('invalid domain')
    for label in domain.split('.'):
        if not 1 <= len(label) <= 63 or label[0] == '-' or label[-1] == '-' or any(
            not (c.isascii() and (c.isalnum() or c == '-')) for c in label
        ):
            raise ValueError('invalid domain')
    return domain


def murmurhash3(value, seed=0):
    data = value.encode('utf-8')
    mask = 0xffffffff
    h = seed & mask
    def rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & mask
    for start in range(0, len(data) // 4 * 4, 4):
        k = int.from_bytes(data[start:start+4], 'little')
        k = rotate((k * 0xcc9e2d51) & mask, 15) * 0x1b873593 & mask
        h ^= k
        h = (rotate(h, 13) * 5 + 0xe6546b64) & mask
    tail = data[len(data)//4*4:]
    if tail:
        k = int.from_bytes(tail, 'little')
        h ^= rotate((k * 0xcc9e2d51) & mask, 15) * 0x1b873593 & mask
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85ebca6b & mask
    h ^= h >> 13
    h = h * 0xc2b2ae35 & mask
    return (h ^ (h >> 16)) & mask


@dataclass(frozen=True)
class Record:
    domain: str
    ip: str
    ttl: int = 3600


class DatasetManager:
    def __init__(self, records, page_size=8, seed=0, created_at=None):
        if page_size < 1:
            raise ValueError('page size must be positive')
        unique = {}
        for record in records:
            domain = normalize(record.domain)
            ip = str(ipaddress.IPv4Address(record.ip))
            if not 1 <= record.ttl <= 604800:
                raise ValueError('TTL must be between 1 and 604800 seconds')
            if domain in unique:
                raise ValueError('duplicate domain: ' + domain)
            unique[domain] = Record(domain, ip, record.ttl)
        if not unique:
            raise ValueError('empty dataset')
        self.page_size = page_size
        self.seed = seed
        self.created_at = time.time() if created_at is None else created_at
        count = math.ceil(len(unique) / page_size)
        if count > 8192:
            raise ValueError('at most 8192 pages supported by this BFV configuration')
        self.pages = [[] for _ in range(count)]
        self.index = {}
        for domain, record in sorted(unique.items()):
            page = murmurhash3(domain, seed) % count
            while len(self.pages[page]) == page_size:
                page = (page + 1) % count
            self.index[domain] = (page, len(self.pages[page]))
            self.pages[page].append(record)
        self.matrix = [[int(ipaddress.IPv4Address(r.ip)) for r in page] +
                       [0] * (page_size - len(page)) for page in self.pages]
        public = {'schema': 1, 'page_size': page_size, 'seed': seed,
                  'created_at': self.created_at,
                  'pages': [[{'domain': r.domain, 'ttl': r.ttl} for r in p] for p in self.pages]}
        # Bind snapshot identity to private answer data as well as the public mapping.
        canonical = json.dumps([public, self.matrix], sort_keys=True).encode()
        public['version'] = hashlib.sha256(canonical).hexdigest()
        self.manifest = public

    @classmethod
    def from_csv(cls, path, **kwargs):
        with open(path, newline='') as f:
            records = [Record(row['domain'], row['ip'], int(row.get('ttl') or 3600))
                       for row in csv.DictReader(f)]
        sidecar = Path(str(path) + '.meta.json')
        if sidecar.exists() and 'created_at' not in kwargs:
            kwargs['created_at'] = json.loads(sidecar.read_text())['created_at']
        return cls(records, **kwargs)
