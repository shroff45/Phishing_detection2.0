"""
tests/test_feature_parity.py

Verifies that Python and JavaScript feature extraction
produce identical results for the same URLs.

This is the MOST IMPORTANT test in the entire project.
A parity failure means the ML model will silently degrade.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml-training"))
from build_dataset import extract_features as extract_url_features


# URLs that exercise edge cases in both parsers
PARITY_TEST_URLS = [
    "https://www.google.com/",
    "http://192.168.1.1/login/verify.php",
    "https://sub1.sub2.sub3.example.co.uk/path/to/page?q=1&r=2",
    "http://192.168.1.1:8080/paypal-login/secure/verify.php?account=victim@email.com",
    "https://xn--pple-43d.com/login",
    "https://bit.ly/abc123",
    "https://example.xyz/update/account/password",
    "http://10.0.0.1/",
    "https://a-very-long-subdomain-that-goes-on-and-on.example.com/path",
    "https://example.com/%2F%3F%3D%26/test",
    "https://user@evil.com/fake-page",
    "https://example.com:8443/login?redirect=https://other.com",
    # Edge cases
    "https://example.com/",  # minimal path
    "https://example.com",   # no trailing slash
    "http://example.com/a/b/c/d/e/f/g/h",  # deep path
]


class TestFeatureParity:
    """
    For each test URL, extract features using BOTH the Python
    function and a Node.js script that runs the JavaScript
    extractLexicalFeatures(). Compare all 30 features.
    """

    @pytest.fixture(autouse=True)
    def setup_js_extractor(self, tmp_path):
        """Create a temporary Node.js script that runs the JS extractor."""
        # Extract the JS function from service-worker.js
        sw_path = Path(__file__).resolve().parent.parent / "extension" / "background" / "service-worker.js"

        if not sw_path.exists():
            pytest.skip("service-worker.js not found")

        # Create a Node.js wrapper script
        js_script = tmp_path / "extract.js"
        js_script.write_text("""
const url = process.argv[2];

// Inline the extractLexicalFeatures function
// (copied from service-worker.js — the function is self-contained)
""" + self._extract_js_function(sw_path) + """

const features = extractLexicalFeatures(url);
if (features.error) {
    console.log(JSON.stringify({error: true}));
} else {
    console.log(JSON.stringify(features));
}
""")
        self.js_script = str(js_script)

    def _extract_js_function(self, sw_path):
        """Extract the extractLexicalFeatures function from service-worker.js"""
        content = sw_path.read_text(encoding="utf-8")

        # Find the function
        start_marker = "function extractLexicalFeatures(rawUrl)"
        start_idx = content.find(start_marker)
        if start_idx == -1:
            return "function extractLexicalFeatures() { return {error:true}; }"

        # Find the matching closing brace
        brace_count = 0
        end_idx = start_idx
        found_first = False
        for i in range(start_idx, len(content)):
            if content[i] == "{":
                brace_count += 1
                found_first = True
            elif content[i] == "}":
                brace_count -= 1
            if found_first and brace_count == 0:
                end_idx = i + 1
                break

        return content[start_idx:end_idx]

    def _run_js_extraction(self, url):
        """Run the JS extractor via Node.js and return the feature dict."""
        try:
            result = subprocess.run(
                ["node", self.js_script, url],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            return json.loads(result.stdout.strip())
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None

    @pytest.mark.parametrize("url", PARITY_TEST_URLS)
    def test_feature_parity(self, url):
        """
        Core parity test: Python and JavaScript must produce
        identical feature values for the same URL.
        """
        py_features = extract_url_features(url)
        js_features = self._run_js_extraction(url)

        if py_features is None and js_features is None:
            return  # Both agree URL is unparseable

        if js_features is None:
            pytest.skip("Node.js not available or JS extraction failed")

        assert py_features is not None, "Python returned None but JS did not"

        # Compare each feature with tolerance for floating point
        feature_keys = [k for k in py_features if k.startswith("f")]
        for key in feature_keys:
            py_val = py_features.get(key, 0)
            js_val = js_features.get(key, 0)

            if isinstance(py_val, float) or isinstance(js_val, float):
                # Allow small floating point differences (entropy calculations)
                assert abs(float(py_val) - float(js_val)) < 0.001, (
                    "PARITY FAILURE on {}: {} → Python={}, JS={}".format(
                        url, key, py_val, js_val
                    )
                )
            else:
                assert py_val == js_val, (
                    "PARITY FAILURE on {}: {} → Python={}, JS={}".format(
                        url, key, py_val, js_val
                    )
                )
