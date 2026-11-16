/**
 * MHR CFW 4.0 Phase 2A.2 — Cloudflare Worker exit
 * Independent HMAC-SHA256 verify + guarded redirects (manual + policy).
 * Secrets: Workers Secrets AUTH_KEY (optional AUTH_KEY_PREV).
 */

const AUTH_WINDOW_SECONDS = 60;
const MAX_REDIRECTS = 5;

const EXCLUDED_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "proxy-connection", "proxy-authorization", "accept-encoding",
  "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
  "x-real-ip", "forwarded", "via", "x-relay-hop",
]);

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function hasCrlf(s) {
  return s.indexOf("\n") >= 0 || s.indexOf("\r") >= 0;
}

function bytesToHex(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, "0");
  return out;
}

async function sha256HexBytes(u8) {
  const dig = await crypto.subtle.digest("SHA-256", u8);
  return bytesToHex(dig);
}

async function sha256HexString(s) {
  return sha256HexBytes(new TextEncoder().encode(s));
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(sig);
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function normalizeHeaders(h) {
  if (!h || typeof h !== "object" || Array.isArray(h)) throw new Error("invalid_h");
  const out = {};
  for (const rawKey of Object.keys(h)) {
    if (typeof rawKey !== "string" || !rawKey) throw new Error("invalid_header_name");
    if (!/^[0-9a-zA-Z!#$%&'*+.^_`|~-]+$/.test(rawKey)) throw new Error("illegal_header_name");
    const key = rawKey.toLowerCase();
    if (EXCLUDED_HEADERS.has(key)) throw new Error("excluded_header");
    if (Object.prototype.hasOwnProperty.call(out, key)) throw new Error("duplicate_header");
    const val = h[rawKey];
    if (typeof val !== "string") throw new Error("header_value_not_string");
    if (hasCrlf(val)) throw new Error("header_crlf");
    out[key] = val;
  }
  return out;
}

async function computeHh(h) {
  const keys = Object.keys(h).sort();
  let ser = "";
  for (const k of keys) ser += k + ":" + h[k] + "\n";
  return sha256HexString(ser);
}

function buildCanonical(ts, n, m, u, r, ct, hh, bh) {
  return (
    "v:4\n" +
    "ts:" + ts + "\n" +
    "n:" + n + "\n" +
    "m:" + m + "\n" +
    "u:" + u + "\n" +
    "r:" + r + "\n" +
    "ct:" + ct + "\n" +
    "hh:" + hh + "\n" +
    "bh:" + bh + "\n"
  );
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function verifyEnvelope(env, secret, prevSecret) {
  if (!env || typeof env !== "object") throw new Error("invalid_envelope");
  if (!secret) throw new Error("server_misconfigured");
  const required = ["v","ts","n","m","u","r","ct","h","b","bh","hh","alg","sig"];
  for (const k of required) {
    if (!Object.prototype.hasOwnProperty.call(env, k)) throw new Error("missing_" + k);
  }
  if (env.v !== 4) throw new Error("unsupported_version");
  if (env.alg !== "HMAC-SHA256") throw new Error("unsupported_alg");
  if (typeof env.sig !== "string" || !/^[0-9a-f]{64}$/.test(env.sig)) throw new Error("invalid_sig");
  if (typeof env.n !== "string" || !/^[0-9a-f]{32,}$/.test(env.n)) throw new Error("invalid_nonce");
  if (typeof env.ts !== "number" || !Number.isInteger(env.ts) || env.ts < 0) throw new Error("invalid_ts");
  if (typeof env.m !== "string" || env.m !== env.m.toUpperCase() || !env.m) throw new Error("invalid_m");
  if (typeof env.u !== "string" || !env.u || hasCrlf(env.u)) throw new Error("invalid_u");
  if (env.r !== 0 && env.r !== 1) throw new Error("invalid_r");
  if (typeof env.ct !== "string" || hasCrlf(env.ct)) throw new Error("invalid_ct");
  if (typeof env.hh !== "string" || !/^[0-9a-f]{64}$/.test(env.hh)) throw new Error("invalid_hh");
  if (typeof env.bh !== "string" || (env.bh !== "" && !/^[0-9a-f]{64}$/.test(env.bh))) throw new Error("invalid_bh");

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - env.ts) > AUTH_WINDOW_SECONDS) throw new Error("ts_expired");

  if (env.h === null || typeof env.h !== "object" || Array.isArray(env.h)) {
    throw new Error("invalid_h");
  }
  const h = normalizeHeaders(env.h);
  if ((await computeHh(h)) !== env.hh) throw new Error("hh_mismatch");

  let rawBody = null;
  if (env.b === null || env.b === undefined) {
    if (env.bh !== "") throw new Error("bh_mismatch");
  } else {
    if (typeof env.b !== "string") throw new Error("invalid_b");
    rawBody = b64ToBytes(env.b);
    const bhCalc = await sha256HexBytes(rawBody);
    if (bhCalc !== env.bh) throw new Error("bh_mismatch");
  }

  const canonical = buildCanonical(env.ts, env.n, env.m, env.u, env.r, env.ct, env.hh, env.bh);
  let expected = await hmacSha256Hex(secret, canonical);
  let ok = constantTimeEqual(expected, env.sig);
  if (!ok && prevSecret) {
    expected = await hmacSha256Hex(prevSecret, canonical);
    ok = constantTimeEqual(expected, env.sig);
  }
  if (!ok) throw new Error("sig_invalid");

  return { m: env.m, u: env.u, r: env.r, ct: env.ct, h, rawBody };
}

/** Normalize URL key for loop detection: drop fragment. */
function urlKey(u) {
  const x = new URL(u.href);
  x.hash = "";
  return x.href;
}

/** Default port for scheme comparison. */
function effectivePort(u) {
  if (u.port) return u.port;
  if (u.protocol === "https:") return "443";
  if (u.protocol === "http:") return "80";
  return "";
}

function sameOrigin(a, b) {
  return (
    a.protocol === b.protocol &&
    a.hostname.toLowerCase() === b.hostname.toLowerCase() &&
    effectivePort(a) === effectivePort(b)
  );
}

/**
 * Destination policy (SSRF-lite). DNS rebinding NOT FULLY MITIGATED.
 * @returns {string|null} error code or null if allowed
 */
function isBlockedDestination(url) {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return "blocked_destination";
  }
  if (url.username || url.password) {
    return "blocked_destination";
  }
  const host = (url.hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host) return "blocked_destination";
  if (host === "localhost" || host.endsWith(".localhost")) {
    return "blocked_destination";
  }
  const metaHosts = new Set([
    "metadata.google.internal",
    "metadata",
    "metadata.google",
  ]);
  if (metaHosts.has(host)) return "blocked_destination";

  // IPv4 literal
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) {
    const o = v4.slice(1, 5).map((x) => parseInt(x, 10));
    if (o.some((n) => n > 255)) return "blocked_destination";
    const [a, b, c] = o;
    if (a === 0) return "blocked_destination";
    if (a === 10) return "blocked_destination";
    if (a === 127) return "blocked_destination";
    if (a === 169 && b === 254) return "blocked_destination";
    if (a === 172 && b >= 16 && b <= 31) return "blocked_destination";
    if (a === 192 && b === 168) return "blocked_destination";
    if (a === 100 && b >= 64 && b <= 127) return "blocked_destination";
    if (a >= 224) return "blocked_destination";
  }
  // IPv6 / bracket form
  if (host.includes(":") || host.startsWith("[")) {
    let h = host.replace(/^\[|\]$/g, "").toLowerCase();
    if (h === "::1" || h === "0:0:0:0:0:0:0:1") return "blocked_destination";
    if (h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) {
      return "blocked_destination";
    }
    if (h.startsWith("ff")) return "blocked_destination";
  }
  return null;
}

function stripBodyHeaders(headers) {
  headers.delete("content-length");
  headers.delete("content-type");
  headers.delete("transfer-encoding");
}

/**
 * Apply redirect method/body rules.
 * Returns { method, body, headers }.
 */
function applyRedirectMethodRules(status, method, body, headers) {
  const h = new Headers(headers);
  let m = method;
  let b = body;

  if (status === 301 || status === 302) {
    if (m === "POST") {
      m = "GET";
      b = undefined;
      stripBodyHeaders(h);
    }
  } else if (status === 303) {
    if (m !== "HEAD") {
      m = "GET";
      b = undefined;
      stripBodyHeaders(h);
    }
  }
  // 307/308: keep method and body
  return { method: m, body: b, headers: h };
}

/**
 * Drain/cancel intermediate response body so resources are not held.
 */
async function discardBody(resp) {
  try {
    if (resp.body && typeof resp.body.cancel === "function") {
      await resp.body.cancel();
      return;
    }
  } catch (_) { /* ignore */ }
  try {
    await resp.arrayBuffer();
  } catch (_) { /* ignore */ }
}

/**
 * Guarded fetch: always redirect=manual.
 * r=0: return first response (including 3xx).
 * r=1: follow up to MAX_REDIRECTS with policy on every hop.
 */
async function fetchWithRedirectGuard(initialUrl, method, headers, body, rFlag) {
  let url = new URL(initialUrl);
  let block = isBlockedDestination(url);
  if (block) throw new Error(block);

  let currentMethod = method;
  let currentBody = body;
  let currentHeaders = new Headers(headers);

  const visited = new Set();
  let redirectsFollowed = 0;

  for (;;) {
    block = isBlockedDestination(url);
    if (block) throw new Error(block);

    const key = urlKey(url);
    if (visited.has(key)) throw new Error("redirect_loop");
    visited.add(key);

    const fetchOpts = {
      method: currentMethod,
      headers: currentHeaders,
      redirect: "manual",
    };
    if (currentBody !== undefined && currentBody !== null) {
      fetchOpts.body = currentBody;
    }

    const resp = await fetch(url.toString(), fetchOpts);
    const status = resp.status;

    if (!REDIRECT_STATUS.has(status)) {
      return resp;
    }

    // r=0: surface 3xx to client, do not follow
    if (rFlag === 0) {
      return resp;
    }

    // r=1: follow under policy
    if (redirectsFollowed >= MAX_REDIRECTS) {
      await discardBody(resp);
      throw new Error("too_many_redirects");
    }

    const loc = resp.headers.get("Location");
    if (!loc) {
      await discardBody(resp);
      throw new Error("missing_location");
    }

    let next;
    try {
      next = new URL(loc, url);
    } catch (_) {
      await discardBody(resp);
      throw new Error("blocked_destination");
    }

    if (next.username || next.password) {
      await discardBody(resp);
      throw new Error("blocked_destination");
    }

    block = isBlockedDestination(next);
    if (block) {
      await discardBody(resp);
      throw new Error(block);
    }

    // cross-origin: strip credentials
    if (!sameOrigin(url, next)) {
      currentHeaders.delete("authorization");
      currentHeaders.delete("cookie");
    }

    const adj = applyRedirectMethodRules(
      status,
      currentMethod,
      currentBody,
      currentHeaders
    );
    currentMethod = adj.method;
    currentBody = adj.body;
    currentHeaders = adj.headers;

    await discardBody(resp);
    redirectsFollowed += 1;
    url = next;
  }
}

async function responseToClientJson(resp) {
  const buffer = await resp.arrayBuffer();
  const uint8 = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < uint8.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, uint8.subarray(i, i + chunkSize));
  }
  const base64 = btoa(binary);
  const responseHeaders = {};
  resp.headers.forEach((v, k) => {
    responseHeaders[k] = v;
  });
  return { s: resp.status, h: responseHeaders, b: base64 };
}

export default {
  async fetch(request, env) {
    try {
      if (request.headers.get("x-relay-hop") === "1") {
        return json({ e: "loop detected" }, 508);
      }

      const secret = (env && env.AUTH_KEY) || "";
      const prevSecret = (env && env.AUTH_KEY_PREV) || "";

      let bodyText;
      try {
        bodyText = await request.text();
      } catch (e) {
        return json({ e: "invalid_body" }, 400);
      }

      let req;
      try {
        req = JSON.parse(bodyText);
      } catch (e) {
        return json({ e: "invalid_json" }, 400);
      }

      if (!req || req.v !== 4 || !req.sig) {
        return json({ e: "unauthorized", detail: "signed_envelope_required" }, 401);
      }

      let verified;
      try {
        verified = await verifyEnvelope(req, secret, prevSecret);
      } catch (err) {
        return json({ e: "unauthorized", detail: String(err.message || err) }, 401);
      }

      let targetUrl;
      try {
        targetUrl = new URL(verified.u);
      } catch (e) {
        return json({ e: "bad url" }, 400);
      }

      const headers = new Headers();
      for (const [k, v] of Object.entries(verified.h)) {
        headers.set(k, v);
      }
      if (verified.ct) headers.set("content-type", verified.ct);
      headers.set("x-relay-hop", "1");

      let resp;
      try {
        resp = await fetchWithRedirectGuard(
          targetUrl,
          verified.m,
          headers,
          verified.rawBody,
          verified.r
        );
      } catch (err) {
        const msg = String(err.message || err);
        const controlled = new Set([
          "blocked_destination",
          "redirect_loop",
          "too_many_redirects",
          "missing_location",
        ]);
        if (controlled.has(msg)) {
          return json({ e: msg }, 400);
        }
        throw err;
      }

      const out = await responseToClientJson(resp);
      return json(out);
    } catch (err) {
      return json({ e: String(err) }, 500);
    }
  },
};

// Exported for unit tests (Node). Cloudflare ignores extra exports on default worker.
export {
  isBlockedDestination,
  applyRedirectMethodRules,
  sameOrigin,
  urlKey,
  MAX_REDIRECTS,
  REDIRECT_STATUS,
};
