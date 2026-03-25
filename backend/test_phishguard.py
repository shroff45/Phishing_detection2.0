import requests, json, sys

print('='*60)
print('PHISHGUARD LIVE INTEGRATION TEST')
print('='*60)

# Test 1: Check response schema
print('\n[TEST 1] Response Schema Check')
try:
    r = requests.post('http://localhost:7860/api/v1/analyze/quick', 
        json={'url': 'https://google.com'})
    data = r.json()
    keys = set(data.keys())
    print(f'  Status: {r.status_code}')
    print(f'  Keys returned: {sorted(keys)}')

    has_reasons = 'reasons' in data
    has_signals = 'signals' in data
    print(f'  Has reasons: {has_reasons}')
    print(f'  Has signals: {has_signals}')

    # Test 2: Check threat_intel schema
    print('\n[TEST 2] Threat Intel Schema Check')
    ti = data.get('threat_feed') or data.get('threat_intel') or {}
    ti_keys = set(ti.keys())
    ti_name = "threat_feed" if "threat_feed" in data else ("threat_intel" if "threat_intel" in data else "MISSING")
    print(f'  Threat intel key name: {ti_name}')
    print(f'  Threat intel fields: {sorted(ti_keys)}')

    has_feeds_checked = 'feeds_checked' in ti
    has_confidence = 'confidence' in ti
    print(f'  Has feeds_checked: {has_feeds_checked}')
    print(f'  Has confidence: {has_confidence}')

    # Test 3: False positive check
    print('\n[TEST 3] False Positive Check')
    score = data.get('score', -1)
    verdict = data.get('verdict', 'unknown')
    print(f'  google.com score: {score}')
    print(f'  google.com verdict: {verdict}')
    if verdict in ('suspicious', 'phishing', 'dangerous'):
        print(f'  FALSE POSITIVE: google.com flagged as {verdict}!')
    else:
        print(f'  Correct: google.com is safe')
except Exception as e:
    print(f'  Error: {e}')

# Test 4: Test known safe sites
print('\n[TEST 4] Safe Site Batch Test')
safe_sites = ['https://www.google.com', 'https://github.com', 'https://stackoverflow.com']
for site in safe_sites:
    try:
        r2 = requests.post('http://localhost:7860/api/v1/analyze/quick',
            json={'url': site}, timeout=15)
        d2 = r2.json()
        v = d2.get('verdict', '?')
        s = d2.get('score', -1)
        print(f'  {site}: verdict={v}, score={s}')
    except Exception as e:
        print(f'  {site}: ERROR - {e}')

# Test 5: CORS verification
print('\n[TEST 5] CORS Verification')
try:
    r3 = requests.options('http://localhost:7860/api/v1/analyze/quick',
        headers={
            'Origin': 'chrome-extension://testextension123',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type'
        })
    origin_header = r3.headers.get('access-control-allow-origin', 'MISSING')
    print(f'  Allow-Origin: {origin_header}')
except Exception as e:
    print(f'  Error: {e}')

print('\n' + '='*60)
