import unittest

from cryptotoolbox import update_check


class UpdateCheckTests(unittest.TestCase):
    def test_version_parse_and_compare(self):
        self.assertTrue(update_check.is_newer("v2.0.1", "2.0.0"))
        self.assertFalse(update_check.is_newer("2.0.0", "2.0.0"))
        self.assertTrue(update_check.is_newer("v2.1", "2.0.9"))
        self.assertFalse(update_check.is_newer("v2.0.0", "2.0.1"))
        self.assertEqual(update_check.parse_version("v1.2.3-beta"), (1, 2, 3))

    def test_parse_release(self):
        payload = {
            "tag_name": "v2.1.0",
            "name": "v2.1.0",
            "html_url": "https://github.com/Draina233/cryptotoolbox/releases/tag/v2.1.0",
            "body": "更新说明",
            "published_at": "2026-10-20T10:00:00Z",
        }
        info = update_check.parse_release(payload)
        self.assertIsNotNone(info)
        self.assertEqual(info.version, "2.1.0")
        self.assertEqual(info.notes, "更新说明")
        self.assertIsNone(update_check.parse_release({"tag_name": "", "html_url": ""}))
        self.assertIsNone(update_check.parse_release({
            "tag_name": "v1", "html_url": "javascript:alert(1)"
        }))


if __name__ == "__main__":
    unittest.main()
