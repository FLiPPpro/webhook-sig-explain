import os, subprocess, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
S = os.path.join(ROOT, "samples")


def run(*args):
    p = subprocess.run([sys.executable, os.path.join(ROOT, "whsig.py")] + list(args),
                       capture_output=True, text=True)
    return p.returncode, p.stdout


class T(unittest.TestCase):
    def test_github_published_vector(self):
        code, out = run("--provider", "github", "--body", os.path.join(S, "github_docs_body.txt"),
                        "--header", "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                        "--secret", "It's a Secret to Everybody")
        self.assertEqual(code, 0, out)

    def test_slack_published_vector(self):
        code, out = run("--provider", "slack", "--body", os.path.join(S, "slack_docs_body.txt"),
                        "--header", "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
                        "--secret", "8f742231b10e8888abcd99yyyzzz85a5",
                        "--timestamp", "1531420618", "--now", "1531420618")
        self.assertEqual(code, 0, out)

    def test_slack_stale_timestamp_rejected(self):
        code, out = run("--provider", "slack", "--body", os.path.join(S, "slack_docs_body.txt"),
                        "--header", "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
                        "--secret", "8f742231b10e8888abcd99yyyzzz85a5", "--timestamp", "1531420618")
        self.assertEqual(code, 1, out)
        self.assertIn("TIMESTAMP REJECTED", out)

    def test_stripe_diagnoses_both_causes(self):
        hdr = open(os.path.join(S, "stripe_header.txt")).read()
        code, out = run("--provider", "stripe", "--body", os.path.join(S, "stripe_body_as_received.json"),
                        "--header", hdr, "--secret-file", os.path.join(S, "stripe_secret_with_newline.txt"),
                        "--now", "1790000100")
        self.assertEqual(code, 1, out)
        self.assertIn("stripped from the secret", out)
        self.assertIn("trailing newline removed", out)

    def test_malformed_header_is_unknown_not_invalid(self):
        code, out = run("--provider", "stripe", "--body", os.path.join(S, "stripe_body_as_received.json"),
                        "--header", "garbage", "--secret", "x")
        self.assertEqual(code, 2, out)

    def test_missing_body_is_unknown(self):
        code, out = run("--provider", "github", "--body", "/nonexistent", "--header", "sha256=00", "--secret", "x")
        self.assertEqual(code, 2, out)


if __name__ == "__main__":
    unittest.main()
