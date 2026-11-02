"""DNS/domain behavior, source isolation, caching and protocol failures."""
from copy import deepcopy
import unittest
from unittest.mock import Mock, patch

import requests

from demo import demo_telemetry
from dns_lookup import DNSClient, RECORD_TYPES, normalize_answer
from indicators import parse_indicator, validate_domain
from reporting import build_ticket_note
from scanner import EnrichmentClient, evaluate_risk

DOMAIN = "example.com"


def dns_payload(kind="A", value="93.184.215.14", ttl=60, rcode=0):
    return {"Status": rcode, "AD": True, "TC": False,
            "Question": [{"name": DOMAIN + ".", "type": RECORD_TYPES[kind]}],
            "Answer": ([{"name": DOMAIN + ".", "type": RECORD_TYPES[kind], "TTL": ttl, "data": value}]
                       if value is not None and not rcode else [])}


def http(payload, code=200):
    result = Mock(status_code=code)
    result.json.return_value = payload
    return result


class ValidationTests(unittest.TestCase):
    def test_domains_are_canonical_and_idn_supported(self):
        self.assertEqual(parse_indicator(" Example.COM. "), ("domain", DOMAIN))
        self.assertEqual(validate_domain("żółw.pl"), "xn--w-uga1v8h.pl")
        self.assertEqual(parse_indicator("8.8.8.8"), ("ipv4", "8.8.8.8"))

    def test_urls_local_names_and_malformed_domains_rejected_before_network(self):
        session = Mock()
        client = EnrichmentClient("key", session)
        for value in ("https://example.com", "example.com/path", "example.com:443", "user@example.com",
                      "localhost", "device.local", "host.invalid", "host.internal", "host.onion",
                      "*.example.com", "_dmarc.example.com", "a..com", "-a.com", "a-.com", "a.123",
                      "999.1.1.1", "a" * 64 + ".com", "a.com..", "a.com\n.evil.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                client.fetch(value)
        session.get.assert_not_called()


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.client = DNSClient(self.session)

    def test_six_record_types_and_partial_failure(self):
        values = {"A": "93.184.215.14", "AAAA": "2606:2800:220:1:248:1893:25c8:1946",
                  "CNAME": None, "MX": "10 mail.example.com.", "NS": "ns.example.com.", "TXT": '"v=spf1 -all"'}
        def answer(url, **kwargs):
            kind = kwargs["params"]["type"]
            if kind == "MX":
                raise requests.Timeout("No response")
            return http(dns_payload(kind, values[kind]))
        self.session.get.side_effect = answer
        result = self.client.resolve(DOMAIN)
        self.assertEqual(self.session.get.call_count, 6)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["data"]["resolved_ipv4"], ["93.184.215.14"])
        self.assertEqual(result["data"]["queries"]["MX"]["status"], "error")
        self.assertEqual(result["data"]["queries"]["CNAME"]["status"], "no_data")
        for call in self.session.get.call_args_list:
            self.assertEqual(call.args[0], "https://dns.google/resolve")
            self.assertEqual(call.kwargs["params"]["edns_client_subnet"], "0.0.0.0/0")
            self.assertNotIn("x-apikey", call.kwargs["headers"])
            self.assertFalse(call.kwargs["allow_redirects"])

    def test_cache_honors_short_ttl_and_returns_copies(self):
        self.session.get.return_value = http(dns_payload(ttl=5))
        with patch("dns_lookup.time.monotonic", return_value=100):
            first = self.client.query(DOMAIN, "A")
            first["records"].clear()
        with patch("dns_lookup.time.monotonic", return_value=104):
            second = self.client.query(DOMAIN, "A")
        self.assertTrue(second["cache_hit"])
        self.assertEqual(len(second["records"]), 1)
        self.assertEqual(self.session.get.call_count, 1)
        with patch("dns_lookup.time.monotonic", return_value=106):
            self.assertFalse(self.client.query(DOMAIN, "A")["cache_hit"])
        self.assertEqual(self.session.get.call_count, 2)

    def test_zero_ttl_not_cached(self):
        self.session.get.return_value = http(dns_payload(ttl=0))
        self.client.query(DOMAIN, "A")
        self.client.query(DOMAIN, "A")
        self.assertEqual(self.session.get.call_count, 2)

    def test_nxdomain_nodata_servfail_and_truncation_are_distinct(self):
        for payload, status, rcode in ((dns_payload(rcode=3), "no_data", 3),
                                       (dns_payload(value=None), "no_data", 0),
                                       (dns_payload(rcode=2), "error", 2),
                                       ({**dns_payload(), "TC": True}, "error", 0)):
            with self.subTest(payload=payload):
                result = normalize_answer(payload, DOMAIN, "A")
                self.assertEqual(result["status"], status)
                self.assertEqual(result["rcode"], rcode)
                self.assertFalse(result["records"])

    def test_malformed_payloads_are_errors(self):
        bad_ip = dns_payload(value="not-an-address")
        mismatched = dns_payload()
        mismatched["Question"][0]["name"] = "other.com."
        for payload in ({}, [], bad_ip, mismatched):
            with self.subTest(payload=payload):
                self.session.get.return_value = http(payload)
                self.assertEqual(DNSClient(self.session).query(DOMAIN, "A")["status"], "error")

    def test_alias_chain_preserved_and_private_answer_not_contacted(self):
        payload = dns_payload(value="10.0.0.1")
        payload["Answer"].insert(0, {"name": DOMAIN + ".", "type": 5, "TTL": 60, "data": "edge.example.com."})
        self.session.get.return_value = http(payload)
        result = self.client.query(DOMAIN, "A")
        self.assertEqual({row["type"] for row in result["records"]}, {"A", "CNAME"})
        self.assertEqual(self.session.get.call_count, 1)
        self.assertEqual(self.session.get.call_args.args[0], "https://dns.google/resolve")

    def test_http_and_json_failures(self):
        for code, status in ((429, "rate_limited"), (500, "error"), (302, "error")):
            self.session.get.return_value = http({}, code)
            self.assertEqual(self.client.query(DOMAIN, "A")["status"], status)
        self.session.get.return_value = http({})
        self.session.get.return_value.json.side_effect = requests.exceptions.JSONDecodeError("bad", "x", 0)
        self.assertEqual(self.client.query(DOMAIN, "A")["status"], "error")


class DomainPipelineTests(unittest.TestCase):
    def test_domain_uses_one_vt_domain_request_and_never_shodan(self):
        session = Mock()
        vt = {"data": {"id": DOMAIN, "type": "domain", "attributes": {
            "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 10, "undetected": 20},
            "registrar": "Example Registrar", "creation_date": 1704067200,
        }}}
        def answer(url, **kwargs):
            if "virustotal" in url:
                self.assertEqual(url, f"https://www.virustotal.com/api/v3/domains/{DOMAIN}")
                self.assertEqual(kwargs["headers"]["x-apikey"], "private-key")
                return http(vt)
            self.assertEqual(url, "https://dns.google/resolve")
            self.assertNotIn("x-apikey", kwargs["headers"])
            kind = kwargs["params"]["type"]
            return http(dns_payload(kind, "93.184.215.14" if kind == "A" else None))
        session.get.side_effect = answer
        report = evaluate_risk(EnrichmentClient("private-key", session).fetch("EXAMPLE.COM."))
        self.assertEqual(report["indicator"], DOMAIN)
        self.assertNotIn("ip", report)
        self.assertNotIn("shodan", report["sources"])
        self.assertEqual(report["priority"], "HIGH")
        self.assertEqual(report["sources"]["virustotal"]["data"]["registrar"], "Example Registrar")
        self.assertEqual(session.get.call_count, 7)
        self.assertNotIn("private-key", str(report))

    def test_domain_dns_without_key_does_not_create_a_verdict(self):
        session = Mock()
        session.get.side_effect = lambda url, **kw: http(dns_payload(kw["params"]["type"], None))
        report = evaluate_risk(EnrichmentClient(session=session).fetch(DOMAIN))
        self.assertIsNone(report["priority_score"])
        self.assertEqual(report["sources"]["dns"]["status"], "no_data")
        self.assertEqual(session.get.call_count, 6)

    def test_domain_and_ip_share_vt_quota(self):
        client = EnrichmentClient("key", Mock())
        client._session.get.return_value = http({}, code=500)
        client.fetch(DOMAIN)
        result = client.fetch("8.8.8.8")
        self.assertEqual(result["sources"]["virustotal"]["status"], "rate_limited")

    def test_domain_demo_export_and_priority_ignore_dns_record_count(self):
        with patch("requests.Session.get", side_effect=AssertionError("Network forbidden")):
            data = demo_telemetry("Domain & DNS")
            report = evaluate_risk(data)
            note = build_ticket_note(report)
            self.assertIn("portal.example.invalid", note)
            self.assertIn("### DNS snapshot", note)
            self.assertIn("SYNTHETIC DATA", note)
            data["sources"]["dns"]["data"]["records"] *= 20
            self.assertEqual(evaluate_risk(data)["priority_score"], report["priority_score"])


if __name__ == "__main__":
    unittest.main()
