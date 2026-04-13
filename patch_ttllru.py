import re

code = open("backend/app/services/threat_intel.py").read()

cache_code = """
# ── Global Cache for Threat Feeds ─────────────────────────────────────────
class ThreatFeedCache:
    def __init__(self, capacity: int = 1000, ttl_seconds: int = 3600):
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

_threat_cache = ThreatFeedCache()

"""

insert_pos = code.find("# ═══════════════════════════════════════════════════════════════════════════\n# THREAT FEED CHECKING")
code = code[:insert_pos] + cache_code + code[insert_pos:]

with open("backend/app/services/threat_intel.py", "w") as f:
    f.write(code)
