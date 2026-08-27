import json
import unittest
from unittest.mock import patch

from vps_audit.ai_review import review_with_provider, test_ai_provider as run_provider_test


class FakeResponse:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return json.dumps(self.value).encode("utf-8")


def review_json(user="account-001"):
    return json.dumps(
        {
            "overall_assessment": "needs review",
            "cases": [
                {
                    "user": user,
                    "assessment": "needs_review",
                    "confidence": 0.6,
                    "facts": ["synthetic fact"],
                    "benign_explanations": ["possible proxy"],
                    "missing_evidence": ["device mapping"],
                    "recommended_action": "manual review",
                }
            ],
        }
    )


def report():
    return {
        "summary": {"event_count": 1, "finding_count": 1, "flagged_user_count": 1},
        "users": [{"user": "alice", "risk_score": 30, "severity": "medium"}],
        "findings": [
            {
                "rule_id": "TEST",
                "user": "alice",
                "severity": "medium",
                "summary": "source 198.51.100.9",
                "evidence": [{"source_ip": "198.51.100.9", "command": "secret command"}],
            }
        ],
        "policy": "manual review",
    }


class AiReviewTests(unittest.TestCase):
    def test_responses_provider_uses_custom_base_url_and_restores_alias(self):
        provider = {
            "base_url": "https://ai.example.test/v1",
            "api_mode": "responses",
            "model": "custom-model",
            "timeout_seconds": 15,
        }
        response = {"ok": True, "output_text": review_json()}
        with patch("vps_audit.ai_review.urllib.request.urlopen", return_value=FakeResponse(response)) as urlopen:
            result = review_with_provider(report(), provider, "secret-key")
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(request.full_url, "https://ai.example.test/v1/responses")
        self.assertEqual(payload["model"], "custom-model")
        self.assertFalse(payload["store"])
        self.assertEqual(result["cases"][0]["user"], "alice")
        serialized = request.data.decode("utf-8")
        self.assertNotIn("198.51.100.9", serialized)
        self.assertNotIn("secret command", serialized)

    def test_chat_completions_provider_uses_json_object_mode(self):
        provider = {
            "base_url": "https://compatible.example/v1/",
            "api_mode": "chat_completions",
            "model": "vendor-model",
            "timeout_seconds": 20,
        }
        response = {"choices": [{"message": {"content": "```json\n" + review_json() + "\n```"}}]}
        with patch("vps_audit.ai_review.urllib.request.urlopen", return_value=FakeResponse(response)) as urlopen:
            result = review_with_provider(report(), provider, "secret-key")
        payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(urlopen.call_args.args[0].full_url, "https://compatible.example/v1/chat/completions")
        self.assertEqual(payload["response_format"], {"type": "json_object"})
        self.assertEqual(result["cases"][0]["assessment"], "needs_review")

    def test_unknown_account_alias_is_rejected(self):
        provider = {
            "base_url": "https://ai.example/v1",
            "api_mode": "responses",
            "model": "model",
            "timeout_seconds": 10,
        }
        response = {"output_text": review_json("real-user-name")}
        with patch("vps_audit.ai_review.urllib.request.urlopen", return_value=FakeResponse(response)):
            with self.assertRaisesRegex(RuntimeError, "unknown account alias"):
                review_with_provider(report(), provider, "secret-key")

    def test_manual_provider_test_uses_only_synthetic_report(self):
        provider = {
            "base_url": "https://ai.example/v1",
            "api_mode": "responses",
            "model": "model",
            "timeout_seconds": 10,
        }
        with patch("vps_audit.ai_review.review_with_provider") as review, patch(
            "vps_audit.ai_review.time.monotonic", side_effect=[10.0, 10.25]
        ):
            result = run_provider_test(provider, "secret-key")
        synthetic = review.call_args.args[0]
        self.assertEqual(synthetic["users"][0]["user"], "connectivity-test")
        self.assertEqual(result["latency_ms"], 250)


if __name__ == "__main__":
    unittest.main()
