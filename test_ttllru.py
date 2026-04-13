import time
from collections import OrderedDict

class TTL_LRUCache:
    def __init__(self, capacity: int, ttl_seconds: int):
        self.capacity = capacity
        self.ttl = ttl_seconds
        self.cache = OrderedDict()

    def get(self, key):
        if key not in self.cache:
            return None
        value, timestamp = self.cache[key]
        if time.time() - timestamp > self.ttl:
            del self.cache[key]
            return None
        self.cache.move_to_end(key)
        return value

    def set(self, key, value):
        if key in self.cache:
            del self.cache[key]
        elif len(self.cache) >= self.capacity:
            self.cache.popitem(last=False)
        self.cache[key] = (value, time.time())

c = TTL_LRUCache(2, 5)
c.set("a", 1)
c.set("b", 2)
print(c.get("a"))
c.set("c", 3)
print(c.get("b"))
