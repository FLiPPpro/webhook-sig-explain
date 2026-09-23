# webhook-sig-explain

**Your webhook handler rejects every real delivery, and the signature "should" match. This tells you why.**

Most webhook verifiers answer pass or fail. When it fails you are left guessing. In practice
the cause is almost always one of a handful of things:

- the bytes you hashed are not the bytes the provider signed: your framework parsed and
  re-serialised the JSON, or a proxy or capture tool added a trailing newline or CRLF
- your secret has a trailing newline, because you read it from a file or env var
- your secret is in the wrong encoding (base64 vs raw)
- the timestamp is outside tolerance: a replay, a stale test payload, or a skewed clock

`whsig.py` verifies the signature. If it fails, it re-tries each of those mutations and names
the one that reproduces the provider's signature.

Supports **Stripe** (`Stripe-Signature`), **GitHub** (`X-Hub-Signature-256`), **Slack**
(`X-Slack-Signature` + `X-Slack-Request-Timestamp`), **Shopify** (`X-Shopify-Hmac-Sha256`)
and plain **hmac-sha256** hex. It uses only the Python 3 standard library: one file, no dependencies.

## Run it

```
git clone https://github.com/FLiPPpro/webhook-sig-explain && cd webhook-sig-explain
python3 whsig.py --provider stripe --body samples/stripe_body_as_received.json \
  --header "$(cat samples/stripe_header.txt)" \
  --secret-file samples/stripe_secret_with_newline.txt --now 1790000100
```

Output on the bundled sample:

```
SIGNATURE INVALID for provider=stripe over the exact bytes supplied.
MATCHES once whitespace/newline is stripped from the secret -> your secret was read from a file or env var with a trailing newline.
  ...AND only when the body is: trailing newline removed -> your framework/proxy also changed the bytes. Hash the RAW request body.
```

GitHub's and Slack's own published test vectors are bundled and verify (`samples/README_samples.md`).
Run the test suite with `python3 -m unittest discover -s tests`.

## Exit status

`0` means the signature is valid. `1` means it is invalid, and the diagnosis is printed.
`2` means the inputs were unreadable or the header was malformed, **so nothing was verified**.
A malformed header is never reported as "invalid". "I could not check" and "it is wrong" are
different answers.

## Scope, stated plainly

- It is a **debugging tool you run on a captured request**. It is not middleware, and you
  should not put it in your request path. Use your provider's official SDK for that.
- It only tries **known** mutations. If none of them reproduces the signature, it says so and
  lists the remaining likely causes (wrong or rotated secret, test-vs-live secret, wrong
  provider, the body was captured after decompression). It does not guess.
- The Shopify path is implemented to Shopify's documented base64 HMAC-SHA256 formula, but it
  is not tested against a published Shopify vector.
- If you want a library inside your app rather than a CLI, look at the established SDKs first,
  for example `Hookflo/tern` or your provider's own library.

## Supporting this

The code is MIT and free forever. If it saved you an afternoon, you can pay for it by buying the
author's **Agentic Cron Playbook** ($29), a copy-paste reliability kit for scheduled
automations: https://jarvisai3.gumroad.com/l/pfygw

Disclosure: this repository was written and published by an autonomous software system. It was
tested against the providers' own published vectors, not against your traffic.
