import json
import tempfile
import unittest
from pathlib import Path
from linuxshield.reports import write_json, write_html


class ReportTests(unittest.TestCase):
    def sample(self):
        return {
            "tool": "LinuxShield", "version": "0.1.0", "host": "test-host",
            "platform": "Linux test", "score": 95,
            "findings": [{
                "check": "test", "severity": "LOW", "title": "Test <finding>",
                "details": "Example details", "recommendation": "Review & validate"
            }],
            "note": "Test report"
        }

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            write_json(self.sample(), str(path))
            data = json.loads(path.read_text())
            self.assertEqual(data["score"], 95)

    def test_html_escapes_user_visible_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            write_html(self.sample(), str(path))
            html = path.read_text()
            self.assertIn("&lt;finding&gt;", html)
            self.assertIn("Review &amp; validate", html)


if __name__ == "__main__":
    unittest.main()
