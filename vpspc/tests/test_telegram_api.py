import json
import unittest
from unittest.mock import patch

from vps_audit.telegram import TelegramTransientError, edit_message_text, get_updates, send_message


class FakeResponse:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return json.dumps(self.value).encode("utf-8")


class TelegramApiTests(unittest.TestCase):
    def test_send_message_posts_json_keyboard_without_putting_token_in_body(self):
        keyboard = {"inline_keyboard": [[{"text": "状态", "callback_data": "menu:status"}]]}
        with patch(
            "vps_audit.telegram.urllib.request.urlopen",
            return_value=FakeResponse({"ok": True, "result": {"message_id": 1}}),
        ) as urlopen:
            send_message("secret-token", "-100123", "hello", reply_markup=keyboard)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["chat_id"], "-100123")
        self.assertEqual(payload["reply_markup"], keyboard)
        self.assertNotIn("secret-token", request.data.decode("utf-8"))
        self.assertEqual(request.headers["Content-type"], "application/json")

    def test_get_updates_tracks_offset_and_allowed_update_types(self):
        response = {"ok": True, "result": [{"update_id": 44, "message": {"text": "/status"}}]}
        with patch(
            "vps_audit.telegram.urllib.request.urlopen", return_value=FakeResponse(response)
        ) as urlopen:
            updates = get_updates("secret-token", 40, timeout=12)
        self.assertEqual(updates[0]["update_id"], 44)
        payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(payload["offset"], 40)
        self.assertEqual(payload["timeout"], 12)
        self.assertEqual(payload["allowed_updates"], ["message", "callback_query"])

    def test_network_timeout_is_classified_as_transient(self):
        with patch(
            "vps_audit.telegram.urllib.request.urlopen", side_effect=TimeoutError("timed out")
        ):
            with self.assertRaises(TelegramTransientError):
                get_updates("secret-token", None, timeout=5)

    def test_edit_message_posts_message_id_and_keyboard(self):
        keyboard = {"inline_keyboard": [[{"text": "下一页", "callback_data": "discover:1"}]]}
        with patch(
            "vps_audit.telegram.urllib.request.urlopen",
            return_value=FakeResponse({"ok": True, "result": {"message_id": 77}}),
        ) as urlopen:
            edit_message_text("secret-token", "-100123", 77, "updated", reply_markup=keyboard)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["chat_id"], "-100123")
        self.assertEqual(payload["message_id"], 77)
        self.assertEqual(payload["reply_markup"], keyboard)


if __name__ == "__main__":
    unittest.main()
