import asyncio
from collections import OrderedDict

_threat_cache = OrderedDict()
_MAX_CACHE_SIZE = 1000

async def check_threat_feeds(url: str) -> dict:
    if url in _threat_cache:
        _threat_cache.move_to_end(url)
        return _threat_cache[url]

    await asyncio.sleep(0.1) # Simulate network call
    result = {"url": url, "flagged": False}

    if len(_threat_cache) >= _MAX_CACHE_SIZE:
        _threat_cache.popitem(last=False)
    _threat_cache[url] = result

    return result

async def main():
    print(await check_threat_feeds("http://example.com"))
    print(await check_threat_feeds("http://example.com"))

asyncio.run(main())
