"""
MHR CFW 4.0 Phase 2A — Signed Envelope (HMAC-SHA256).

Implements PHASE_2A_CRYPTOGRAPHIC_FINAL_SPEC.md
Canonical form: newline-separated fixed-order fields, trailing LF, UTF-8.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from typing import Any, Mapping, Optional

ALG = "HMAC-SHA256"
VERSION = 4
DEFAULT_WINDOW_SECONDS = 60
HARD_MAX_WINDOW_SECONDS = 300
NONCE_HEX_RE = re.compile(r"^[0-9a-f]{32,}$")
SIG_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
HEADER_NAME_RE = re.compile(r"^[0-9a-zA-Z!#$%&'*+.^_`|~-]+$")

# Must not appear inside signed application header map `h`.
EXCLUDED_HEADER_NAMES = frozenset({
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "proxy-connection",
    "proxy-authorization",
    "accept-encoding",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "via",
    "x-relay-hop",
})


class EnvelopeError(ValueError):
    """Invalid envelope construction or verification."""


def _require_no_crlf(name: str, value: str) -> str:
    if "\n" in value or "\r" in value:
        raise EnvelopeError(f"{name} must not contain CR/LF")
    return value


def normalize_signed_headers(headers: Optional[Mapping[str, Any]]) -> dict[str, str]:
    """Return lower-cased single-value header map; reject illegal names/values.

    None is allowed only as a convenience for seal() when caller omits headers
    (treated as {}). JSON null / list / string must be rejected by verify_envelope
    before calling this with a non-mapping.
    """
    if headers is None:
        return {}
    if isinstance(headers, (str, bytes, list, tuple)):
        raise EnvelopeError("h must be an object")
    if not isinstance(headers, Mapping):
        raise EnvelopeError("h must be an object")

    out: dict[str, str] = {}
    for raw_key, raw_val in headers.items():
        if not isinstance(raw_key, str) or not raw_key:
            raise EnvelopeError("header name must be non-empty string")
        if not HEADER_NAME_RE.match(raw_key):
            raise EnvelopeError(f"illegal header name: {raw_key!r}")
        key = raw_key.lower()
        if key in EXCLUDED_HEADER_NAMES:
            raise EnvelopeError(f"excluded header not allowed in signed h: {key}")
        if key in out:
            raise EnvelopeError(f"duplicate header after lowercasing: {key}")
        if not isinstance(raw_val, str):
            raise EnvelopeError(f"header value must be string: {key}")
        _require_no_crlf(f"header:{key}", raw_val)
        out[key] = raw_val
    return out


def compute_hh(headers: Mapping[str, str]) -> str:
    """SHA-256 hex of canonical header serialization."""
    parts: list[str] = []
    for key in sorted(headers.keys(), key=lambda s: s.encode("utf-8")):
        parts.append(f"{key}:{headers[key]}\n")
    serialized = "".join(parts)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_bh(raw_body: Optional[bytes]) -> str:
    """SHA-256 hex of raw body; empty string token when body is absent (None)."""
    if raw_body is None:
        return ""
    return hashlib.sha256(raw_body).hexdigest()


def build_canonical(
    *,
    ts: int,
    n: str,
    m: str,
    u: str,
    r: int,
    ct: str,
    hh: str,
    bh: str,
) -> str:
    """Newline-separated canonical string with trailing LF."""
    if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0:
        raise EnvelopeError("ts must be non-negative int")
    if not NONCE_HEX_RE.match(n):
        raise EnvelopeError("invalid nonce")
    if not m or m != m.upper() or any(c.isspace() for c in m):
        raise EnvelopeError("m must be non-empty uppercase method")
    _require_no_crlf("u", u)
    if not u:
        raise EnvelopeError("u required")
    if r not in (0, 1):
        raise EnvelopeError("r must be 0 or 1")
    _require_no_crlf("ct", ct)
    if hh and not SIG_HEX_RE.match(hh):
        # hh is also 64 hex
        if not re.match(r"^[0-9a-f]{64}$", hh):
            raise EnvelopeError("invalid hh")
    if bh != "" and not re.match(r"^[0-9a-f]{64}$", bh):
        raise EnvelopeError("invalid bh")

    lines = [
        f"v:{VERSION}",
        f"ts:{ts}",
        f"n:{n}",
        f"m:{m}",
        f"u:{u}",
        f"r:{r}",
        f"ct:{ct}",
        f"hh:{hh}",
        f"bh:{bh}",
    ]
    return "\n".join(lines) + "\n"


def sign_canonical(secret: str, canonical: str) -> str:
    if not secret:
        raise EnvelopeError("secret required")
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def seal_envelope(
    *,
    secret: str,
    method: str,
    url: str,
    headers: Optional[Mapping[str, Any]] = None,
    body: Optional[bytes] = None,
    content_type: Optional[str] = None,
    redirect: int = 0,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
) -> dict[str, Any]:
    """Build a complete v4 signed envelope dict ready for JSON serialization."""
    if not secret or not str(secret).strip():
        raise EnvelopeError("auth secret missing")

    m = (method or "").upper()
    u = url or ""
    r = 0 if not redirect else 1
    if r not in (0, 1):
        r = 1 if redirect else 0

    h = normalize_signed_headers(headers)
    hh = compute_hh(h)

    if body is None:
        b_field = None
        bh = ""
    else:
        if not isinstance(body, (bytes, bytearray)):
            raise EnvelopeError("body must be bytes or None")
        raw = bytes(body)
        b_field = base64.b64encode(raw).decode("ascii")
        bh = compute_bh(raw)

    ct = content_type if content_type is not None else ""
    if ct is None:
        ct = ""
    _require_no_crlf("ct", ct)

    ts_v = int(time.time()) if ts is None else int(ts)
    n_v = nonce if nonce is not None else secrets.token_hex(16)
    if not NONCE_HEX_RE.match(n_v):
        raise EnvelopeError("invalid nonce")

    canonical = build_canonical(
        ts=ts_v, n=n_v, m=m, u=u, r=r, ct=ct, hh=hh, bh=bh
    )
    sig = sign_canonical(secret, canonical)

    return {
        "v": VERSION,
        "ts": ts_v,
        "n": n_v,
        "m": m,
        "u": u,
        "r": r,
        "ct": ct,
        "h": h,
        "b": b_field,
        "bh": bh,
        "hh": hh,
        "alg": ALG,
        "sig": sig,
    }


def verify_envelope(
    env: Mapping[str, Any],
    secret: str,
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    now: Optional[int] = None,
    previous_secret: Optional[str] = None,
) -> dict[str, Any]:
    """
    Verify envelope. Returns a normalized dict of signed fields on success.
    Raises EnvelopeError on failure.
    """
    if not isinstance(env, Mapping):
        raise EnvelopeError("envelope must be object")
    if not secret:
        raise EnvelopeError("secret required")

    try:
        v = env["v"]
        ts = env["ts"]
        n = env["n"]
        m = env["m"]
        u = env["u"]
        r = env["r"]
        ct = env["ct"]
        h_raw = env["h"]
        b = env["b"]
        bh = env["bh"]
        hh = env["hh"]
        alg = env["alg"]
        sig = env["sig"]
    except KeyError as exc:
        raise EnvelopeError(f"missing field: {exc}") from exc

    if v != VERSION:
        raise EnvelopeError("unsupported version")
    if alg != ALG:
        raise EnvelopeError("unsupported alg")
    if not isinstance(sig, str) or not SIG_HEX_RE.match(sig):
        raise EnvelopeError("invalid sig")
    if not isinstance(n, str) or not NONCE_HEX_RE.match(n):
        raise EnvelopeError("invalid nonce")
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise EnvelopeError("invalid ts")
    if not isinstance(m, str) or m != m.upper() or not m:
        raise EnvelopeError("invalid m")
    if not isinstance(u, str) or not u:
        raise EnvelopeError("invalid u")
    _require_no_crlf("u", u)
    if r not in (0, 1) or isinstance(r, bool):
        # JSON may decode 0/1 as int; bool is subclass of int in Python — reject bool
        if r is True or r is False:
            raise EnvelopeError("invalid r")
        if r not in (0, 1):
            raise EnvelopeError("invalid r")
    if not isinstance(ct, str):
        raise EnvelopeError("invalid ct")
    _require_no_crlf("ct", ct)
    if not isinstance(hh, str) or not re.match(r"^[0-9a-f]{64}$", hh):
        raise EnvelopeError("invalid hh")
    if not isinstance(bh, str) or (bh != "" and not re.match(r"^[0-9a-f]{64}$", bh)):
        raise EnvelopeError("invalid bh")

    window = max(1, min(int(window_seconds), HARD_MAX_WINDOW_SECONDS))
    now_v = int(time.time()) if now is None else int(now)
    if abs(now_v - ts) > window:
        raise EnvelopeError("ts_expired")

    # h must be a JSON object (dict). null / array / string are invalid.
    if h_raw is None or isinstance(h_raw, (str, bytes, list, tuple)):
        raise EnvelopeError("h must be an object")
    if not isinstance(h_raw, Mapping):
        raise EnvelopeError("h must be an object")
    h = normalize_signed_headers(h_raw)
    if compute_hh(h) != hh:
        raise EnvelopeError("hh_mismatch")

    if b is None:
        if bh != "":
            raise EnvelopeError("bh_mismatch")
        raw_body: Optional[bytes] = None
    else:
        if not isinstance(b, str):
            raise EnvelopeError("invalid b")
        try:
            raw_body = base64.b64decode(b, validate=True)
        except Exception as exc:
            raise EnvelopeError("invalid_base64") from exc
        if compute_bh(raw_body) != bh:
            raise EnvelopeError("bh_mismatch")

    canonical = build_canonical(
        ts=ts, n=n, m=m, u=u, r=int(r), ct=ct, hh=hh, bh=bh
    )

    def _ok(sec: str) -> bool:
        expected = sign_canonical(sec, canonical)
        return hmac.compare_digest(expected, sig)

    if _ok(secret):
        pass
    elif previous_secret and _ok(previous_secret):
        pass
    else:
        raise EnvelopeError("sig_invalid")

    return {
        "v": VERSION,
        "ts": ts,
        "n": n,
        "m": m,
        "u": u,
        "r": int(r),
        "ct": ct,
        "h": h,
        "b": b,
        "bh": bh,
        "hh": hh,
        "alg": ALG,
        "sig": sig,
        "raw_body": raw_body,
    }


def standard_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
