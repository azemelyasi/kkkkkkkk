/**
 * Phase 2A.2 — unit tests for Worker redirect policy helpers (Node, not live CF).
 */
import { strict as assert } from "assert";
import {
  isBlockedDestination,
  applyRedirectMethodRules,
  sameOrigin,
  urlKey,
  MAX_REDIRECTS,
} from "../script/worker.js";

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    console.log("PASS", name);
    passed++;
  } catch (e) {
    console.log("FAIL", name, e.message);
    failed++;
  }
}

test("R2 private IP blocked", () => {
  assert.equal(isBlockedDestination(new URL("http://192.168.1.1/")), "blocked_destination");
  assert.equal(isBlockedDestination(new URL("http://10.0.0.2/")), "blocked_destination");
  assert.equal(isBlockedDestination(new URL("http://172.16.0.1/")), "blocked_destination");
});

test("R3 localhost blocked", () => {
  assert.equal(isBlockedDestination(new URL("http://localhost/")), "blocked_destination");
  assert.equal(isBlockedDestination(new URL("http://127.0.0.1/")), "blocked_destination");
});

test("R4 metadata host blocked", () => {
  assert.equal(isBlockedDestination(new URL("http://metadata.google.internal/")), "blocked_destination");
});

test("R9 non-http scheme blocked", () => {
  assert.equal(isBlockedDestination(new URL("ftp://example.com/")), "blocked_destination");
});

test("R13 userinfo blocked", () => {
  assert.equal(isBlockedDestination(new URL("https://user:pass@example.com/")), "blocked_destination");
});

test("public https allowed", () => {
  assert.equal(isBlockedDestination(new URL("https://example.com/path")), null);
});

test("R16 POST+301 -> GET no body", () => {
  const h = new Headers({ "content-type": "application/json", "content-length": "2" });
  const r = applyRedirectMethodRules(301, "POST", new Uint8Array([1, 2]), h);
  assert.equal(r.method, "GET");
  assert.equal(r.body, undefined);
  assert.equal(r.headers.get("content-type"), null);
  assert.equal(r.headers.get("content-length"), null);
});

test("R16 POST+302 -> GET", () => {
  const r = applyRedirectMethodRules(302, "POST", new Uint8Array([1]), new Headers());
  assert.equal(r.method, "GET");
  assert.equal(r.body, undefined);
});

test("301 GET stays GET", () => {
  const r = applyRedirectMethodRules(301, "GET", undefined, new Headers());
  assert.equal(r.method, "GET");
});

test("R15 HEAD+303 stays HEAD", () => {
  const r = applyRedirectMethodRules(303, "HEAD", undefined, new Headers());
  assert.equal(r.method, "HEAD");
});

test("R15 POST+303 -> GET", () => {
  const r = applyRedirectMethodRules(303, "POST", new Uint8Array([1]), new Headers({ "content-type": "x" }));
  assert.equal(r.method, "GET");
  assert.equal(r.body, undefined);
});

test("R17 POST+307 keeps method and body", () => {
  const body = new Uint8Array([9]);
  const r = applyRedirectMethodRules(307, "POST", body, new Headers({ "content-type": "x" }));
  assert.equal(r.method, "POST");
  assert.equal(r.body, body);
  assert.equal(r.headers.get("content-type"), "x");
});

test("R17 POST+308 keeps", () => {
  const body = new Uint8Array([9]);
  const r = applyRedirectMethodRules(308, "POST", body, new Headers());
  assert.equal(r.method, "POST");
  assert.equal(r.body, body);
});

test("R14 port change is cross-origin", () => {
  const a = new URL("https://example.com/");
  const b = new URL("https://example.com:8443/");
  assert.equal(sameOrigin(a, b), false);
});

test("same origin default ports", () => {
  const a = new URL("https://example.com/");
  const b = new URL("https://example.com:443/");
  assert.equal(sameOrigin(a, b), true);
});

test("urlKey drops fragment", () => {
  const a = urlKey(new URL("https://example.com/a#x"));
  const b = urlKey(new URL("https://example.com/a#y"));
  assert.equal(a, b);
});

test("MAX_REDIRECTS is 5", () => {
  assert.equal(MAX_REDIRECTS, 5);
});

console.log(`\nSummary: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
