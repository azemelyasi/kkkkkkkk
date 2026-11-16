/**
 * MHR CFW 4.0 Phase 2A — Google Apps Script relay with independent HMAC verify.
 * Secrets: Script Properties AUTH_KEY (required), optional AUTH_KEY_PREV, WORKER_URL.
 * Do NOT put real secrets in this source file.
 */
var AUTH_WINDOW_SECONDS = 60;

var EXCLUDED_HEADERS = {
  host: 1, connection: 1, "content-length": 1, "transfer-encoding": 1,
  "proxy-connection": 1, "proxy-authorization": 1, "accept-encoding": 1,
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "x-real-ip": 1, forwarded: 1, via: 1, "x-relay-hop": 1
};

function _props() { return PropertiesService.getScriptProperties(); }
function _getSecret() { return _props().getProperty("AUTH_KEY") || ""; }
function _getSecretPrev() { return _props().getProperty("AUTH_KEY_PREV") || ""; }
function _getWorkerUrl() {
  var u = _props().getProperty("WORKER_URL");
  if (u) return u;
  return "https://YOUR-WORKER-NAME.YOUR-SUBDOMAIN.workers.dev";
}
function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
function _bytesToHex(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if (b < 0) b += 256;
    var h = b.toString(16);
    if (h.length === 1) out += "0";
    out += h;
  }
  return out;
}
function _sha256Hex(s) {
  return _bytesToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8));
}
function _hmacSha256Hex(secret, message) {
  return _bytesToHex(Utilities.computeHmacSignature(
    Utilities.MacAlgorithm.HMAC_SHA_256, message, secret, Utilities.Charset.UTF_8));
}
function _constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function _hasCrlf(s) { return s.indexOf("\n") >= 0 || s.indexOf("\r") >= 0; }

function _normalizeHeaders(h) {
  if (!h || typeof h !== "object" || Array.isArray(h)) throw new Error("invalid_h");
  var out = {};
  var keys = Object.keys(h);
  for (var i = 0; i < keys.length; i++) {
    var rawKey = keys[i];
    if (typeof rawKey !== "string" || !rawKey) throw new Error("invalid_header_name");
    if (!/^[0-9a-zA-Z!#$%&'*+.^_`|~-]+$/.test(rawKey)) throw new Error("illegal_header_name");
    var key = rawKey.toLowerCase();
    if (EXCLUDED_HEADERS[key]) throw new Error("excluded_header");
    if (Object.prototype.hasOwnProperty.call(out, key)) throw new Error("duplicate_header");
    var val = h[rawKey];
    if (typeof val !== "string") throw new Error("header_value_not_string");
    if (_hasCrlf(val)) throw new Error("header_crlf");
    out[key] = val;
  }
  return out;
}
function _computeHh(h) {
  var keys = Object.keys(h).sort();
  var ser = "";
  for (var i = 0; i < keys.length; i++) ser += keys[i] + ":" + h[keys[i]] + "\n";
  return _sha256Hex(ser);
}
function _computeBhFromB64(b) {
  if (b === null || typeof b === "undefined") return "";
  if (typeof b !== "string") throw new Error("invalid_b");
  var bytes = Utilities.base64Decode(b);
  return _bytesToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes));
}
function _buildCanonical(ts, n, m, u, r, ct, hh, bh) {
  return "v:4\n" + "ts:" + ts + "\n" + "n:" + n + "\n" + "m:" + m + "\n" +
    "u:" + u + "\n" + "r:" + r + "\n" + "ct:" + ct + "\n" + "hh:" + hh + "\n" + "bh:" + bh + "\n";
}

function _verifyEnvelope(env) {
  if (!env || typeof env !== "object") throw new Error("invalid_envelope");
  var secret = _getSecret();
  if (!secret) throw new Error("server_misconfigured");
  var required = ["v","ts","n","m","u","r","ct","h","b","bh","hh","alg","sig"];
  for (var i = 0; i < required.length; i++) {
    if (!Object.prototype.hasOwnProperty.call(env, required[i])) throw new Error("missing_" + required[i]);
  }
  if (env.v !== 4) throw new Error("unsupported_version");
  if (env.alg !== "HMAC-SHA256") throw new Error("unsupported_alg");
  if (typeof env.sig !== "string" || !/^[0-9a-f]{64}$/.test(env.sig)) throw new Error("invalid_sig");
  if (typeof env.n !== "string" || !/^[0-9a-f]{32,}$/.test(env.n)) throw new Error("invalid_nonce");
  if (typeof env.ts !== "number" || env.ts !== Math.floor(env.ts) || env.ts < 0) throw new Error("invalid_ts");
  if (typeof env.m !== "string" || env.m !== env.m.toUpperCase() || !env.m) throw new Error("invalid_m");
  if (typeof env.u !== "string" || !env.u || _hasCrlf(env.u)) throw new Error("invalid_u");
  if (env.r !== 0 && env.r !== 1) throw new Error("invalid_r");
  if (typeof env.ct !== "string" || _hasCrlf(env.ct)) throw new Error("invalid_ct");
  if (typeof env.hh !== "string" || !/^[0-9a-f]{64}$/.test(env.hh)) throw new Error("invalid_hh");
  if (typeof env.bh !== "string" || (env.bh !== "" && !/^[0-9a-f]{64}$/.test(env.bh))) throw new Error("invalid_bh");

  var now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - env.ts) > AUTH_WINDOW_SECONDS) throw new Error("ts_expired");

  if (env.h === null || typeof env.h !== "object" || Array.isArray(env.h)) {
    throw new Error("invalid_h");
  }
  var h = _normalizeHeaders(env.h);
  if (_computeHh(h) !== env.hh) throw new Error("hh_mismatch");
  var bhCalc = _computeBhFromB64(env.b);
  if (bhCalc !== env.bh) throw new Error("bh_mismatch");
  if ((env.b === null || typeof env.b === "undefined") && env.bh !== "") throw new Error("bh_mismatch");

  var canonical = _buildCanonical(env.ts, env.n, env.m, env.u, env.r, env.ct, env.hh, env.bh);
  var expected = _hmacSha256Hex(secret, canonical);
  var ok = _constantTimeEqual(expected, env.sig);
  if (!ok) {
    var prev = _getSecretPrev();
    if (prev) ok = _constantTimeEqual(_hmacSha256Hex(prev, canonical), env.sig);
  }
  if (!ok) throw new Error("sig_invalid");

  return {
    v: 4, ts: env.ts, n: env.n, m: env.m, u: env.u, r: env.r, ct: env.ct,
    h: h, b: (env.b === null || typeof env.b === "undefined") ? null : env.b,
    bh: env.bh, hh: env.hh, alg: "HMAC-SHA256", sig: env.sig
  };
}

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req && Array.isArray(req.q)) return _doBatch(req.q);
    if (req && req.v === 4 && req.sig) {
      var verified = _verifyEnvelope(req);
      return _forwardToWorker(verified);
    }
    return _json({ e: "unauthorized", detail: "signed_envelope_required" });
  } catch (err) {
    var msg = String(err && err.message ? err.message : err);
    return _json({ e: "unauthorized", detail: msg });
  }
}

function _forwardToWorker(verifiedEnvelope) {
  var workerUrl = _getWorkerUrl();
  var resp = UrlFetchApp.fetch(workerUrl, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(verifiedEnvelope),
    muteHttpExceptions: true,
    followRedirects: true
  });
  try {
    return _json(JSON.parse(resp.getContentText()));
  } catch (e) {
    return _json({ e: "invalid worker response", raw: resp.getContentText() });
  }
}

function _doBatch(items) {
  var fetchArgs = [];
  var errorMap = {};
  var workerUrl = _getWorkerUrl();
  for (var i = 0; i < items.length; i++) {
    try {
      var verified = _verifyEnvelope(items[i]);
      fetchArgs.push({
        _i: i,
        _o: {
          url: workerUrl, method: "post", contentType: "application/json",
          payload: JSON.stringify(verified), muteHttpExceptions: true, followRedirects: true
        }
      });
    } catch (err) {
      errorMap[i] = "unauthorized:" + String(err.message || err);
    }
  }
  var responses = fetchArgs.length ? UrlFetchApp.fetchAll(fetchArgs.map(function (x) { return x._o; })) : [];
  var results = [];
  var rIdx = 0;
  for (var j = 0; j < items.length; j++) {
    if (Object.prototype.hasOwnProperty.call(errorMap, j)) results.push({ e: errorMap[j] });
    else {
      var resp = responses[rIdx++];
      try { results.push(JSON.parse(resp.getContentText())); }
      catch (e) { results.push({ e: "invalid worker response", raw: resp.getContentText() }); }
    }
  }
  return _json({ q: results });
}

function doGet(e) {
  return HtmlService.createHtmlOutput(
    "<!DOCTYPE html><html><head><title>My App</title></head>" +
    '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
    "<h1>Relay Active</h1><p>Signed envelope (v4) required.</p></body></html>"
  );
}
