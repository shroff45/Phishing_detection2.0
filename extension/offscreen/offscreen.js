/**
 * PhishGuard — Offscreen Worker v0.3.0
 *
 * Runs ONNX Runtime Web.
 * Takes the heavy AI floating-point math out of the service worker.
 */

// Configure ORT
ort.env.wasm.numThreads = 1;
ort.env.wasm.wasmPaths = "../lib/"; // Need ort-wasm.wasm and ort-wasm-simd.wasm here

let urlSession = null;

const MSG = {
  RUN_URL_MODEL: "runUrlModel"
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.target !== "offscreen") return false;

  if (message.action === MSG.RUN_URL_MODEL) {
    runUrlInference(message.payload)
      .then(score => sendResponse({ score }))
      .catch(err => {
        console.error("[PhishGuard Offscreen] Inference error:", err);
        sendResponse({ score: 0.5 }); // Error defaults broadly to unsure
      });
    return true; // async
  }
});

async function runUrlInference(features) {
  if (!urlSession) {
    console.log("[PhishGuard Offscreen] Loading ONNX model from ../models/phishguard_url_xgb.onnx");
    urlSession = await ort.InferenceSession.create("../models/phishguard_url_xgb.onnx", {
      executionProviders: ['wasm']
    });
  }

  // Convert dictionary of features to Float32Array in EXACT order of training
  // Note: For hackathon purpose, we are assuming features dict keys are sorted nicely
  // or we map them. Here we just take Object.values assuming ordered creation.
  
  // TO BE SAFE: explicitly order them (f01 to f30)
  const fNames = [
    "f01_urlLength", "f02_hostnameLength", "f03_pathLength", "f04_queryLength",
    "f05_dotCountUrl", "f06_dotCountHost", "f07_hyphenCountUrl", "f08_hyphenCountHost",
    "f09_underscoreCount", "f10_atSymbolCount", "f11_digitCountUrl", "f12_digitCountHost",
    "f13_digitToLetterRatio", "f14_subdomainCount", "f15_pathDepth", "f16_queryParamCount",
    "f17_isIpAddress", "f18_entropyUrl", "f19_entropyHost", "f20_entropyPath",
    "f21_specialCharCount", "f22_hasPort", "f23_isHttps", "f24_hasSuspiciousTld",
    "f25_hasPunycode", "f26_isShortener", "f27_keywordHits", "f28_encodedCharCount",
    "f29_doubleSlashCount", "f30_longestSubdomainLen"
  ];

  const arr = new Float32Array(30);
  for (let i = 0; i < 30; i++) {
    const key = fNames[i];
    arr[i] = typeof features[key] === 'number' ? features[key] : 0.0;
  }

  const tensor = new ort.Tensor('float32', arr, [1, 30]);
  const feed = { [urlSession.inputNames[0]]: tensor };
  const out = await urlSession.run(feed);
  
  // XGBoost ONNX output is usually a probability array in the second output
  const outputName = urlSession.outputNames[1]; 
  // out[outputName].data is an array [prob_class_0, prob_class_1]
  const probPhishing = out[outputName].data[1]; 

  return probPhishing;
}
