#!/usr/bin/env python3
"""webhook-sig-explain: verify a webhook signature, and when it fails, say WHY.

Most verifiers answer pass/fail. The failure you actually debug is "my handler
rejects every real webhook" - and the cause is almost always that the bytes you
hashed are not the bytes the provider signed (a framework re-serialised the JSON,
a proxy added a newline), or the secret is in the wrong encoding, or the
timestamp is outside tolerance. This tool re-tries the known mutations and tells
you which one reproduces the provider's signature.

Standard library only. MIT licence.

Exit status: 0 = signature valid, 1 = invalid (diagnosis printed),
             2 = inputs unreadable / header malformed (nothing was verified).
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time

PROVIDERS = ("stripe", "github", "slack", "shopify", "hmac-sha256")


def _hex(key, msg):
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _b64(key, msg):
    return base64.b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode()


def parse_header(provider, header):
    """Return (signatures:list[str], timestamp:str|None). Raises ValueError."""
    header = header.strip()
    if provider == "stripe":
        parts = dict()
        sigs = []
        for item in header.split(","):
            if "=" not in item:
                raise ValueError("Stripe-Signature item without '=': %r" % item)
            k, v = item.split("=", 1)
            if k.strip() == "v1":
                sigs.append(v.strip())
            else:
                parts[k.strip()] = v.strip()
        if "t" not in parts or not sigs:
            raise ValueError("Stripe-Signature needs t=... and at least one v1=...")
        return sigs, parts["t"]
    if provider == "github":
        if not header.startswith("sha256="):
            raise ValueError("X-Hub-Signature-256 must start with 'sha256='")
        return [header[len("sha256="):]], None
    if provider == "slack":
        if not header.startswith("v0="):
            raise ValueError("X-Slack-Signature must start with 'v0='")
        return [header[len("v0="):]], None
    return [header], None


def expected(provider, secret, body, timestamp, secret_is_b64=False):
    key = base64.b64decode(secret) if secret_is_b64 else secret.encode()
    if provider == "stripe":
        return _hex(key, timestamp.encode() + b"." + body)
    if provider == "slack":
        return _hex(key, b"v0:" + timestamp.encode() + b":" + body)
    if provider == "shopify":
        return _b64(key, body)
    return _hex(key, body)


def body_variants(body):
    """Mutations that commonly sit between the provider's bytes and yours."""
    out = [("exact bytes as given", body)]
    if body.endswith(b"\n"):
        out.append(("trailing newline removed", body.rstrip(b"\r\n")))
    else:
        out.append(("trailing newline added", body + b"\n"))
    if b"\r\n" in body:
        out.append(("CRLF converted to LF", body.replace(b"\r\n", b"\n")))
    try:
        obj = json.loads(body.decode("utf-8"))
        out.append(("JSON re-serialised compact (json.dumps separators=(',',':'))",
                    json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()))
        out.append(("JSON re-serialised with default spacing (json.dumps)",
                    json.dumps(obj).encode()))
        out.append(("JSON re-serialised with sorted keys",
                    json.dumps(obj, sort_keys=True).encode()))
    except (ValueError, UnicodeDecodeError):
        pass
    seen, uniq = set(), []
    for label, b in out:          # identical bytes -> report the first cause only
        if b not in seen:
            seen.add(b)
            uniq.append((label, b))
    return uniq


def diagnose(provider, secret, body, header, now, tolerance, ts_override=None):
    lines = []
    try:
        sigs, ts = parse_header(provider, header)
    except ValueError as e:
        return 2, ["HEADER UNREADABLE: %s" % e, "Nothing was verified."]
    if ts_override is not None:
        ts = ts_override
    if provider in ("stripe", "slack"):
        if ts is None:
            return 2, ["HEADER UNREADABLE: no timestamp supplied (use --timestamp for Slack)."]
        if not ts.isdigit():
            return 2, ["HEADER UNREADABLE: timestamp %r is not an integer." % ts]

    def match(b, b64=False):
        exp = expected(provider, secret, b, ts, b64)
        return any(hmac.compare_digest(exp, s) for s in sigs)

    if match(body):
        verdict = ["SIGNATURE VALID for provider=%s over the exact bytes supplied." % provider]
        if ts is not None and abs(now - int(ts)) > tolerance:
            verdict.append("BUT TIMESTAMP REJECTED: %s is %ds from now, tolerance %ds "
                           "(a replay, a stale test payload, or a skewed clock)."
                           % (ts, now - int(ts), tolerance))
            return 1, verdict
        return 0, verdict

    lines.append("SIGNATURE INVALID for provider=%s over the exact bytes supplied." % provider)
    found = []
    for label, b in body_variants(body)[1:]:
        if match(b):
            found.append("MATCHES if the body is: %s -> your framework/proxy changed the "
                         "bytes before you hashed them. Hash the RAW request body." % label)
    if provider != "shopify":
        try:
            if match(body, b64=True):
                found.append("MATCHES if the secret is base64-decoded first -> you are "
                             "passing the secret in the wrong encoding.")
        except (ValueError, base64.binascii.Error):
            pass
    stripped = secret.strip()
    if stripped != secret:
        for label, b in body_variants(body):
            if any(hmac.compare_digest(expected(provider, stripped, b, ts), s) for s in sigs):
                found.append("MATCHES once whitespace/newline is stripped from the secret -> "
                             "your secret was read from a file or env var with a trailing "
                             "newline.")
                if label != "exact bytes as given":
                    found.append("  ...AND only when the body is: %s -> your framework/proxy "
                                 "also changed the bytes. Hash the RAW request body." % label)
                break
    if found:
        lines.extend(found)
    else:
        lines.append("No known mutation reproduces the signature. Remaining causes, in order "
                     "of likelihood: wrong secret (test vs live, or a rotated endpoint "
                     "secret); wrong provider selected; body captured after decompression "
                     "or decoding; the header belongs to a different request.")
    return 1, lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--provider", required=True, choices=PROVIDERS)
    ap.add_argument("--body", required=True, help="file holding the raw request body")
    ap.add_argument("--header", required=True, help="the signature header value")
    ap.add_argument("--secret", help="signing secret (or use --secret-file)")
    ap.add_argument("--secret-file", help="file holding the signing secret, read as-is")
    ap.add_argument("--timestamp", help="Slack: X-Slack-Request-Timestamp value")
    ap.add_argument("--tolerance", type=int, default=300, help="seconds (default 300)")
    ap.add_argument("--now", type=int, help="override current unix time (for tests)")
    a = ap.parse_args(argv)
    try:
        body = open(a.body, "rb").read()
        if a.secret_file:
            secret = open(a.secret_file, "r", encoding="utf-8").read()
        elif a.secret is not None:
            secret = a.secret
        else:
            print("INPUT UNREADABLE: give --secret or --secret-file. Nothing was verified.")
            return 2
    except OSError as e:
        print("INPUT UNREADABLE: %s. Nothing was verified." % e)
        return 2
    header = a.header
    if a.provider == "slack":
        if not a.timestamp:
            print("INPUT UNREADABLE: Slack needs --timestamp. Nothing was verified.")
            return 2
    now = a.now if a.now is not None else int(time.time())
    code, lines = diagnose(a.provider, secret, body, header, now, a.tolerance,
                           ts_override=a.timestamp if a.provider == "slack" else None)
    print("\n".join(lines))
    return code



if __name__ == "__main__":
    sys.exit(main())
