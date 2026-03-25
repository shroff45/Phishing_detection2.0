code = open("backend/app/services/threat_intel.py").read()

import re

new_check_func = """
    # 2. Check Cache
    cached = _threat_cache.get(url)
    if cached:
        logger.debug("threat_feed_cache_hit", url=url)
        return cached

    result = {
"""
code = code.replace("""    result = {""", new_check_func)

new_return = """    _threat_cache.set(url, result)
    return result
"""
# Make sure we replace only the last return result of check_threat_feeds
code = re.sub(r'    return result\s*\n\s*# ════', new_return + '\n\n# ════', code, count=1)

with open("backend/app/services/threat_intel.py", "w") as f:
    f.write(code)
