#!/usr/bin/env python3
"""Phase 2A signed envelope golden vectors + security tests (Python)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from signed_envelope import (  # noqa: E402
    EnvelopeError,
    build_canonical,
    compute_bh,
    compute_hh,
    seal_envelope,
    sign_canonical,
    verify_envelope,
)

DOC_SECRET = "test-secret-for-vectors-only-not-production"


class GoldenVectors(unittest.TestCase):
    def test_v1_simple(self):
        env = seal_envelope(
            secret=DOC_SECRET,
            method="GET",
            url="https://example.com/",
            headers={"Accept": "text/html", "X-Custom": "a"},
            body=None,
            content_type="",
            redirect=0,
            ts=1731780000,
            nonce="a" * 32,
        )
        self.assertEqual(env["hh"], "89f7f091ecabef0c750257452ee181fbb9d34c8710c66fb08d89544a881dc2fc")
        self.assertEqual(env["bh"], "")
        self.assertEqual(env["sig"], "333af7593f49a4a70eefd3973046a8f1a6c0dba9fade9f8c21133ea6e56ced95")
        verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_v2_query(self):
        env = seal_envelope(
            secret=DOC_SECRET, method="GET",
            url="https://example.com/path?q=1&r=2",
            headers={"Accept": "*/*"}, body=None, content_type="", redirect=0,
            ts=1731780000, nonce="b" * 32,
        )
        self.assertEqual(env["sig"], "31b9864986ba7a6423e5cba99ec293d2de1d8b910ffc7093b095e8b0231aec3f")
        verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_v3_unicode_hdr(self):
        env = seal_envelope(
            secret=DOC_SECRET, method="GET", url="https://example.com/",
            headers={"X-Name": "نام"}, body=None, content_type="", redirect=0,
            ts=1731780000, nonce="c" * 32,
        )
        self.assertEqual(env["sig"], "95972d77240d6b6b2ee931b9d21e9a9321551bfa2a45098bbcee9a8fee885e6f")
        verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_v6_empty_bytes_body(self):
        env = seal_envelope(
            secret=DOC_SECRET, method="POST", url="https://example.com/",
            headers={}, body=b"", content_type="text/plain", redirect=0,
            ts=1731780000, nonce="f" * 32,
        )
        self.assertEqual(env["bh"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(env["b"], "")
        self.assertEqual(env["sig"], "e173ccc559678859f42e2ac39640180c3370fab093bf7e410c687e3487244631")
        verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_v7_body_hello(self):
        env = seal_envelope(
            secret=DOC_SECRET, method="POST", url="https://example.com/",
            headers={}, body=b"hello", content_type="text/plain", redirect=0,
            ts=1731780000, nonce="1" * 32,
        )
        self.assertEqual(env["b"], "aGVsbG8=")
        self.assertEqual(env["bh"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(env["sig"], "8fcec7ca2598b87f4c39d738cf5dd38140d108664e1b9a649953228a1da26dd4")
        verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_v8_special_url(self):
        env = seal_envelope(
            secret=DOC_SECRET, method="GET",
            url="https://example.com/a&b=c?x=%2F",
            headers={}, body=None, content_type="", redirect=1,
            ts=1731780000, nonce="2" * 32,
        )
        self.assertEqual(env["sig"], "c86cd6f3eb4f18ddddf78546c176b157bc2ff68e4105dab7a4399a4e3f84b4ea")
        verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_no_body_distinct_from_empty_bytes(self):
        a = seal_envelope(secret=DOC_SECRET, method="GET", url="https://example.com/",
                          body=None, ts=1731780000, nonce="e" * 32)
        b = seal_envelope(secret=DOC_SECRET, method="POST", url="https://example.com/",
                          body=b"", content_type="text/plain", ts=1731780000, nonce="f" * 32)
        self.assertNotEqual(a["sig"], b["sig"])
        self.assertEqual(a["bh"], "")
        self.assertEqual(b["bh"], compute_bh(b""))


class SecurityTamper(unittest.TestCase):
    def _good(self):
        return seal_envelope(
            secret=DOC_SECRET, method="GET", url="https://example.com/",
            headers={"Accept": "text/html"}, body=None, ts=1731780000, nonce="a" * 32,
        )

    def test_modified_url(self):
        env = self._good()
        env["u"] = "https://evil.example/"
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_modified_method(self):
        env = self._good()
        env["m"] = "POST"
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_modified_header(self):
        env = self._good()
        env["h"] = dict(env["h"])
        env["h"]["accept"] = "application/json"
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_modified_body(self):
        env = seal_envelope(secret=DOC_SECRET, method="POST", url="https://example.com/",
                            body=b"hello", content_type="text/plain",
                            ts=1731780000, nonce="1" * 32)
        env["b"] = "aGVsbG8h"  # hello!
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_modified_ct(self):
        env = self._good()
        env["ct"] = "text/plain"
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_modified_r(self):
        env = self._good()
        env["r"] = 1 if env["r"] == 0 else 0
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_invalid_sig(self):
        env = self._good()
        env["sig"] = "0" * 64
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_expired_ts(self):
        env = self._good()
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000 + 10_000)

    def test_wrong_secret(self):
        env = self._good()
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, "other-secret", now=1731780000)

    def test_missing_secret_seal(self):
        with self.assertRaises(EnvelopeError):
            seal_envelope(secret="", method="GET", url="https://example.com/")

    def test_excluded_header_rejected(self):
        with self.assertRaises(EnvelopeError):
            seal_envelope(secret=DOC_SECRET, method="GET", url="https://example.com/",
                          headers={"Host": "evil"})

    def test_duplicate_header_case(self):
        with self.assertRaises(EnvelopeError):
            seal_envelope(secret=DOC_SECRET, method="GET", url="https://example.com/",
                          headers={"Accept": "a", "accept": "b"})

    def test_unsupported_alg(self):
        env = self._good()
        env["alg"] = "HMAC-SHA1"
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_previous_secret_rotation(self):
        env = self._good()
        verify_envelope(env, "new-secret", previous_secret=DOC_SECRET, now=1731780000)


class PackageStillOk(unittest.TestCase):
    def test_no_k_injection_left(self):
        text = (ROOT / "src" / "domain_fronter.py").read_text(encoding="utf-8")
        self.assertNotIn('"k": self.auth_key', text)
        self.assertIn("seal_envelope", text)



class HeaderStripAndHValidation(unittest.TestCase):
    def test_h_null_rejected(self):
        env = seal_envelope(secret=DOC_SECRET, method="GET", url="https://example.com/",
                            body=None, ts=1731780000, nonce="a" * 32)
        env["h"] = None
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_h_array_rejected(self):
        env = seal_envelope(secret=DOC_SECRET, method="GET", url="https://example.com/",
                            body=None, ts=1731780000, nonce="a" * 32)
        env["h"] = []
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_h_string_rejected(self):
        env = seal_envelope(secret=DOC_SECRET, method="GET", url="https://example.com/",
                            body=None, ts=1731780000, nonce="a" * 32)
        env["h"] = "invalid"
        with self.assertRaises(EnvelopeError):
            verify_envelope(env, DOC_SECRET, now=1731780000)

    def test_build_payload_strips_host_and_does_not_restore(self):
        import sys
        sys.path.insert(0, str(ROOT / "src"))
        from domain_fronter import DomainFronter
        # minimal instance without full connect
        class T:
            _STRIP_HEADERS = DomainFronter._STRIP_HEADERS
            _build_payload = DomainFronter._build_payload
        inst = T()
        headers = {
            "Host": "example.com",
            "Accept-Encoding": "gzip",
            "User-Agent": "TestAgent/1.0",
            "Accept": "text/html",
        }
        payload = DomainFronter._build_payload(inst, "GET", "https://example.com/", headers, b"")
        h = payload.get("h") or {}
        lower = {k.lower(): v for k, v in h.items()}
        self.assertNotIn("host", lower)
        self.assertNotIn("accept-encoding", lower)
        self.assertIn("user-agent", lower)
        self.assertIn("accept", lower)

    def test_build_payload_all_excluded_yields_empty_h(self):
        from domain_fronter import DomainFronter
        inst = type("T", (), {"_STRIP_HEADERS": DomainFronter._STRIP_HEADERS})()
        headers = {"Host": "example.com", "Accept-Encoding": "gzip", "Connection": "keep-alive"}
        payload = DomainFronter._build_payload(inst, "GET", "https://example.com/", headers, b"")
        self.assertEqual(payload.get("h"), {})
        # critical: must NOT restore original headers
        self.assertNotIn("Host", payload.get("h", {}))

    def test_get_with_browser_headers_seals(self):
        from domain_fronter import DomainFronter
        class T:
            auth_key = DOC_SECRET
            _STRIP_HEADERS = DomainFronter._STRIP_HEADERS
            _build_payload = DomainFronter._build_payload
            _seal_relay_payload = DomainFronter._seal_relay_payload
        inst = T()
        headers = {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html",
            "Accept-Encoding": "gzip, deflate",
        }
        payload = DomainFronter._build_payload(inst, "GET", "https://example.com/", headers, b"")
        sealed = DomainFronter._seal_relay_payload(inst, payload)
        self.assertEqual(sealed["v"], 4)
        self.assertIn("user-agent", sealed["h"])
        self.assertNotIn("host", sealed["h"])
        verify_envelope(sealed, DOC_SECRET)

    def test_post_with_body_and_ct(self):
        from domain_fronter import DomainFronter
        class T:
            auth_key = DOC_SECRET
            _STRIP_HEADERS = DomainFronter._STRIP_HEADERS
            _build_payload = DomainFronter._build_payload
            _seal_relay_payload = DomainFronter._seal_relay_payload
        inst = T()
        headers = {"Host": "api.example.com", "Content-Type": "application/json", "User-Agent": "Test"}
        body = b'{"a":1}'
        payload = DomainFronter._build_payload(inst, "POST", "https://api.example.com/x", headers, body)
        sealed = DomainFronter._seal_relay_payload(inst, payload)
        self.assertEqual(sealed["ct"], "application/json")
        self.assertIsNotNone(sealed["b"])
        verify_envelope(sealed, DOC_SECRET)


if __name__ == "__main__":
    unittest.main()
