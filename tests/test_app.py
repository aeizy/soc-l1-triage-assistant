"""Smoke checks against Streamlit's real script runner, with network blocked."""
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from demo import demo_telemetry


class AppTests(unittest.TestCase):
    def test_demo_scenarios_and_live_validation(self):
        with patch("requests.Session.get", side_effect=AssertionError("No network in UI tests")):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py")).run(timeout=45)
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, "85 / 100")
            app.selectbox[0].select("Exposure without flags").run()
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, "0 / 100")
            app.selectbox[0].select("Partial intelligence").run()
            self.assertEqual(app.metric[0].value, "Not assessed")
            app.selectbox[0].select("Domain & DNS").run()
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[2].label, "DNS records")
            self.assertEqual(app.metric[2].value, "6")
            self.assertTrue(any("DNS records" == header.value for header in app.subheader))
            app.selectbox[0].select("Outdated analysis").run()
            self.assertEqual(app.metric[0].value, "Not assessed")
            app.radio[0].set_value("Live").run()
            self.assertFalse(app.exception)
            self.assertEqual(len(app.metric), 0)
            domain_telemetry = demo_telemetry("Domain & DNS")
            domain_telemetry.update(indicator="example.com", mode="live")
            with patch("scanner.EnrichmentClient.fetch", return_value=domain_telemetry):
                app.text_input[0].set_value("example.com")
                app.button[0].click().run()
                self.assertFalse(app.exception)
                self.assertEqual(app.metric[2].value, "6")
            telemetry = demo_telemetry()
            telemetry.update(ip="8.8.8.8", mode="live")
            with patch("scanner.EnrichmentClient.fetch", return_value=telemetry):
                app.text_input[0].set_value("8.8.8.8")
                app.button[0].click().run()
                self.assertFalse(app.exception)
                self.assertEqual(app.metric[0].value, "85 / 100")
                app.run()
                self.assertEqual(app.metric[0].value, "85 / 100")
            app.text_input[0].set_value("127.0.0.1")
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertIn("public unicast", app.error[0].value)
            self.assertEqual(len(app.metric), 0)


if __name__ == "__main__":
    unittest.main()
