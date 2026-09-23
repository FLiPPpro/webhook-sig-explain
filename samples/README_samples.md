# Samples

- `github_docs_body.txt` + GitHub's published test vector (secret `It's a Secret to Everybody`,
  header `sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17`), from
  GitHub's "Validating webhook deliveries" docs. Expected: VALID, exit 0.
- `slack_docs_body.txt` + Slack's published example (secret `8f742231b10e8888abcd99yyyzzz85a5`,
  timestamp `1531420618`, header `v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503`),
  from Slack's "Verifying requests from Slack" docs. Expected: VALID, exit 0.
- `stripe_*` - a synthetic Stripe-shaped case generated for this repo (not a real Stripe
  secret or event). The body file carries a trailing newline the provider never signed,
  and the secret file carries a trailing newline too. Expected: INVALID, exit 1, with both
  causes named.
