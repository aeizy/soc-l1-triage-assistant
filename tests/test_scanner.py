"""Deterministic tests. No real API keys, quota usage or external requests."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import Mock, patch

import requests

from demo import SCENARIOS, demo_telemetry
from reporting import build_ticket_note
from scanner import EnrichmentClient, evaluate_risk, validate_ip

IP = "8.8.8.8"


def response(code=200, payload=None, headers=None):
    result = Mock(status_code=code, headers=headers or {})
    result.json.return_value = payload
    return result


def vt_payload(ip=IP, malicious=0, suspicious=0):
    return {"data": {"id": ip, "type": "ip_address", "attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                "harmless": 20, "undetected": 30, "timeout": 0},
        "last_analysis_date": int(datetime.now(timezone.utc).timestamp()),
    }}}


def shodan_payload(ip=IP):
    return {"ip": ip, "ports": [443, 22, 443], "vulns": ["CVE-DEMO-0001"],
            "tags": ["vpn", "hosting"], "hostnames": []}


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.client = EnrichmentClient("test-secret-do-not-export", self.session)

    def test_rejects_non_public_or_invalid_input_before_any_request(self):
        for ip in ("", "1.2.3.999", "010.0.0.1", "127.0.0.1", "10.0.0.1",
                   "192.168.1.1", "100.64.0.1", "169.254.1.1", "203.0.113.42",
                   "224.0.0.1", "255.255.255.255", "::1", "https://example.com"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                self.client.fetch(ip)
        self.session.get.assert_not_called()
        self.assertEqual(validate_ip(" 8.8.8.8 "), IP)

    def test_missing_key_still_returns_shodan(self):
        self.session.get.return_value = response(payload=shodan_payload())
        report = EnrichmentClient(session=self.session).fetch(IP)
        self.assertEqual(report["sources"]["virustotal"]["status"], "missing_key")
        self.assertEqual(report["sources"]["shodan"]["data"]["ports"], [22, 443])
        self.assertEqual(self.session.get.call_count, 1)
        self.assertNotIn("x-apikey", self.session.get.call_args.kwargs["headers"])
        self.assertEqual(evaluate_risk(report)["priority"], "UNASSESSED")

    def test_partial_failure_preserves_other_source_and_never_exports_key(self):
        self.session.get.side_effect = [requests.Timeout("test-secret-do-not-export"), response(payload=shodan_payload())]
        report = evaluate_risk(self.client.fetch(IP))
        self.assertEqual(report["coverage"], "PARTIAL")
        self.assertEqual(report["priority"], "UNASSESSED")
        self.assertNotIn("test-secret-do-not-export", json.dumps(report))
        self.assertEqual(self.session.get.call_count, 2)

    def test_provider_http_failures_are_explicit(self):
        for code, status in ((401, "auth_error"), (403, "auth_error"), (404, "no_data"),
                             (429, "rate_limited"), (500, "error"), (302, "error")):
            with self.subTest(code=code):
                self.session.get.return_value = response(code)
                report = EnrichmentClient("key", self.session).fetch(IP)
                self.assertEqual(report["sources"]["virustotal"]["status"], status)
                self.assertEqual(evaluate_risk(report)["priority"], "UNASSESSED")

    def test_invalid_json_and_wrong_schema_are_not_clean_reports(self):
        malformed = response()
        malformed.json.side_effect = requests.exceptions.JSONDecodeError("Bad JSON", "x", 0)
        for result in (malformed, response(payload={}), response(payload=[]),
                       response(payload=vt_payload(ip="1.1.1.1"))):
            with self.subTest(result=result):
                self.session.get.return_value = result
                report = EnrichmentClient("key", self.session).fetch(IP)
                self.assertEqual(report["sources"]["virustotal"]["status"], "error")

    def test_incomplete_or_negative_vendor_counts_are_rejected(self):
        for stats in ({"harmless": 20}, {"malicious": -1, "suspicious": 0, "harmless": 1, "undetected": 0},
                      {"malicious": True, "suspicious": 0, "harmless": 1, "undetected": 0}):
            payload = vt_payload()
            payload["data"]["attributes"]["last_analysis_stats"] = stats
            self.session.get.side_effect = [response(payload=payload), response(payload=shodan_payload())]
            report = EnrichmentClient("key", self.session).fetch(IP)
            self.assertEqual(report["sources"]["virustotal"]["status"], "error")

    def test_metadata_without_analysis_remains_unassessed(self):
        payload = vt_payload()
        del payload["data"]["attributes"]["last_analysis_stats"]
        self.session.get.side_effect = [response(payload=payload), response(payload=shodan_payload())]
        report = evaluate_risk(self.client.fetch(IP))
        self.assertEqual(report["priority"], "UNASSESSED")
        self.assertEqual(report["coverage"], "PARTIAL")

    def test_only_timeouts_do_not_count_as_vendor_analysis(self):
        payload = vt_payload()
        payload["data"]["attributes"]["last_analysis_stats"] = {
            "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 20,
        }
        self.session.get.side_effect = [response(payload=payload), response(payload=shodan_payload())]
        report = evaluate_risk(self.client.fetch(IP))
        self.assertIsNone(report["priority_score"])

    def test_success_is_cached_without_mutable_shared_reports(self):
        self.session.get.side_effect = [response(payload=vt_payload()), response(payload=shodan_payload())]
        first = self.client.fetch(IP)
        first["sources"]["shodan"]["data"]["ports"].clear()
        second = self.client.fetch(IP)
        self.assertEqual(self.session.get.call_count, 2)
        self.assertTrue(second["sources"]["virustotal"]["cache_hit"])
        self.assertEqual(second["sources"]["shodan"]["data"]["ports"], [22, 443])
        self.assertNotIn("test-secret", json.dumps(second))
        vt_call, shodan_call = self.session.get.call_args_list
        self.assertEqual(vt_call.kwargs["headers"]["x-apikey"], "test-secret-do-not-export")
        self.assertNotIn("x-apikey", shodan_call.kwargs["headers"])
        self.assertFalse(vt_call.kwargs["allow_redirects"])

    def test_vt_cooldown_does_not_block_shodan(self):
        self.session.get.side_effect = [response(payload=vt_payload()), response(payload=shodan_payload()),
                                        response(payload=shodan_payload("1.1.1.1"))]
        self.client.fetch(IP)
        report = self.client.fetch("1.1.1.1")
        self.assertEqual(report["sources"]["virustotal"]["status"], "rate_limited")
        self.assertEqual(report["sources"]["shodan"]["status"], "success")
        self.assertEqual(self.session.get.call_count, 3)

    def test_retry_after_is_honored(self):
        self.session.get.side_effect = [response(429, headers={"Retry-After": "120"}),
                                        response(payload=shodan_payload()), response(payload=shodan_payload("1.1.1.1"))]
        first = self.client.fetch(IP)
        self.assertEqual(first["sources"]["virustotal"]["retry_after_seconds"], 120)
        second = self.client.fetch("1.1.1.1")
        self.assertGreaterEqual(second["sources"]["virustotal"]["retry_after_seconds"], 119)
        self.assertEqual(self.session.get.call_count, 3)

    def test_local_daily_quota(self):
        self.client._vt_day = datetime.now(timezone.utc).date()
        self.client._vt_requests = 500
        self.session.get.return_value = response(payload=shodan_payload())
        result = self.client.fetch(IP)
        self.assertEqual(result["sources"]["virustotal"]["status"], "rate_limited")
        self.assertEqual(self.session.get.call_count, 1)

    def test_expired_cache_is_refetched(self):
        self.session.get.side_effect = [response(payload=vt_payload()), response(payload=shodan_payload()),
                                        response(payload=vt_payload(malicious=6)), response(payload=shodan_payload())]
        with patch("scanner.time.monotonic", return_value=100):
            self.client.fetch(IP)
        with patch("scanner.time.monotonic", return_value=4000):
            result = self.client.fetch(IP)
        self.assertEqual(result["sources"]["virustotal"]["data"]["stats"]["malicious"], 6)
        self.assertFalse(result["sources"]["virustotal"]["cache_hit"])
        self.assertEqual(self.session.get.call_count, 4)


class PolicyTests(unittest.TestCase):
    def test_priority_boundaries(self):
        for malicious, suspicious, score, priority in (
            (0, 0, 0, "LOW"), (0, 1, 15, "MEDIUM"), (1, 0, 25, "MEDIUM"),
            (2, 0, 45, "MEDIUM"), (4, 1, 60, "MEDIUM"), (5, 0, 70, "HIGH"), (8, 2, 85, "HIGH")
        ):
            with self.subTest(malicious=malicious, suspicious=suspicious):
                data = demo_telemetry()
                data["sources"]["virustotal"]["data"]["stats"].update(malicious=malicious, suspicious=suspicious)
                report = evaluate_risk(data)
                self.assertEqual((report["priority_score"], report["priority"]), (score, priority))

    def test_exposure_alone_does_not_imply_maliciousness(self):
        report = evaluate_risk(demo_telemetry("Exposure without flags"))
        self.assertEqual(report["priority_score"], 0)
        self.assertEqual(report["assessment"], "NO VENDOR FLAGS")
        self.assertNotIn("BENIGN", json.dumps(report))

    def test_no_intelligence_has_no_numeric_score(self):
        report = evaluate_risk(demo_telemetry("No intelligence"))
        self.assertIsNone(report["priority_score"])
        self.assertEqual(report["coverage"], "UNAVAILABLE")

    def test_old_or_undated_unflagged_analysis_needs_fresh_data(self):
        for timestamp in (1, None):
            data = demo_telemetry("Exposure without flags")
            data["sources"]["virustotal"]["data"]["last_analysis_date"] = timestamp
            report = evaluate_risk(data)
            self.assertEqual(report["assessment"], "FRESH DATA REQUIRED")
            self.assertIsNone(report["priority_score"])

    def test_historical_flags_remain_visible_with_age_warning(self):
        data = demo_telemetry()
        data["sources"]["virustotal"]["data"]["last_analysis_date"] = 1
        report = evaluate_risk(data)
        self.assertEqual(report["priority"], "HIGH")
        self.assertEqual(report["vt_freshness"], "STALE")

    def test_scoring_does_not_mutate_evidence(self):
        data = demo_telemetry()
        original = deepcopy(data)
        evaluate_risk(data)
        self.assertEqual(data, original)

    def test_demo_and_notes_never_require_network(self):
        with patch("requests.Session.get", side_effect=AssertionError("Network forbidden")):
            for scenario in SCENARIOS:
                report = evaluate_risk(demo_telemetry(scenario))
                note = build_ticket_note(report)
                self.assertIn("SYNTHETIC DATA", note)
                self.assertIn("not a probability", note)
                self.assertIn("Limitations", note)
                self.assertIn(report["priority"], note)


if __name__ == "__main__":
    unittest.main()
