from collections import OrderedDict
import time


class PageCache:
    def __init__(self, capacity=16):
        self.pages = OrderedDict()
        self.resize(capacity)

    def resize(self, capacity):
        if capacity < 0:
            raise ValueError('negative cache capacity')
        self.capacity = capacity
        while len(self.pages) > capacity:
            self.pages.popitem(last=False)

    def get(self, page, domain):
        entry = self.pages.get(page)
        if entry is None or domain not in entry:
            return None
        ip, expires = entry[domain]
        if expires <= time.time():
            del self.pages[page]
            return None
        self.pages.move_to_end(page)
        return ip, max(0, int(expires - time.time()))

    def put(self, page, records):
        if self.capacity:
            self.pages[page] = records
            self.pages.move_to_end(page)
            while len(self.pages) > self.capacity:
                self.pages.popitem(last=False)
