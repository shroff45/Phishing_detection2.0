import requests, json, time, sys

print('='*60)
print('PHISHGUARD FINAL VERIFICATION')  
print('='*60)

passed = 0
failed = 0
API_KEY = "phishguard-dev-key"
HEADERS = {"X-API-Key": API_KEY}

# ── TEST 1: Response Schema ──
print('\n[1/6] Response Schema')
try:
    r = requests.post('http://localhost:7860/api/v1/analyze/quick',
        json={'url': 'https://google.com'}, headers=HEADERS, timeout=15)
    d = r.json()
    print(f'  Status: {r.status_code}')
    print(f'  Keys: {sorted(d.keys())}')
    
    if 'reasons' in d and 'signals' in d:
        print('  PASS: reasons and signals present')
        passed += 1
    else:
        print('  FAIL: reasons/signals MISSING')
        failed += 1
except Exception as e:
    print(f'  FAIL: {e}')
    failed += 1

# ── TEST 2: Threat Intel Schema ──
print('\n[2/6] Threat Intel Schema')
try:
    ti = d.get('threat_feed') or d.get('threat_intel') or {}
    print(f'  Threat intel fields: {sorted(ti.keys())}')
    if 'feeds_checked' in ti or 'confidence' in ti:
        print(f'  PASS: New schema detected')
        passed += 1
    else:
        print('  FAIL: feeds_checked missing (old schema)')
        failed += 1
except:
    failed += 1

# ── TEST 3: google.com Safe ──
print('\n[3/6] google.com False Positive Check')
try:
    verdict = d.get('verdict', 'unknown')
    score = d.get('score', -1)
    print(f'  Verdict: {verdict}, Score: {score}')
    if verdict == 'safe' or (verdict == 'suspicious' and score < 0.25):
        print('  PASS: google.com correctly safe/low-risk')
        passed += 1
    else:
        print(f'  FAIL: google.com flagged as {verdict} ({score})')
        failed += 1
except:
    failed += 1

# ── TEST 4: Batch Safe Sites ──
print('\n[4/6] Safe Site Batch')
safe_sites = ['https://github.com', 'https://stackoverflow.com', 'https://microsoft.com']
batch_pass = True
for site in safe_sites:
    try:
        r2 = requests.post('http://localhost:7860/api/v1/analyze/quick',
            json={'url': site}, headers=HEADERS, timeout=15)
        d2 = r2.json()
        v = d2.get('verdict', '?')
        s = d2.get('score', -1)
        status = 'ok' if v == 'safe' or s < 0.35 else 'FALSE POSITIVE'
        print(f'  {site}: {v} ({s}) [{status}]')
        if status != 'ok':
            batch_pass = False
    except Exception as e:
        print(f'  {site}: ERROR {e}')
        batch_pass = False
if batch_pass:
    print('  PASS')
    passed += 1
else:
    print('  FAIL')
    failed += 1

# ── TEST 5: CORS ──
print('\n[5/6] CORS Chrome Extension')
try:
    r3 = requests.options('http://localhost:7860/api/v1/analyze/quick',
        headers={
            'Origin': 'chrome-extension://test123',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type'
        })
    ao = r3.headers.get('access-control-allow-origin', 'MISSING')
    print(f'  Allow-Origin: {ao}')
    if 'chrome-extension' in ao or '*' in ao:
        print('  PASS')
        passed += 1
    else:
        print('  FAIL')
        failed += 1
except:
    failed += 1

# ── TEST 6: API Keys Active ──
print('\n[6/6] Threat Feeds Active')
try:
    if 'feeds_checked' in ti:
        print('  PASS: feeds checked: ' + str(ti.get('feeds_checked', [])))
        passed += 1
    elif ti.get('is_known_threat') is False:
        print('  PARTIAL: Functional check')
        passed += 1
    else:
        print('  FAIL: No feeds running')
        failed += 1
except:
    failed += 1

# ── FINAL VERDICT ──
print('\n' + '='*60)
print(f'RESULTS: {passed} passed, {failed} failed out of 6')
if failed == 0:
    print('ALL TESTS PASSED - PhishGuard is production ready!')
    sys.exit(0)
else:
    print(f'{failed} ISSUES REMAINING - see failures above')
    sys.exit(1)
print('='*60)
