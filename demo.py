"""Synthetic reports: no network calls and no claims about real IP reputation."""

from datetime import datetime, timedelta, timezone

from scanner import _normalize_shodan, _normalize_vt, _result, utc_now

SCENARIOS = {
    "Vendor flags": "Multiple vendor flags with exposed services.",
    "Exposure without flags": "Potential CVEs and a VPN tag, with no vendor flags.",
    "Partial intelligence": "Shodan responds while VirusTotal is rate limited.",
    "No intelligence": "Neither source has usable intelligence.",
    "Outdated analysis": "An old report without flags requires fresh evidence.",
    "Domain & DNS": "A synthetic domain report with DNS records and vendor classifications.",
}


def demo_telemetry(scenario="Vendor flags"):
    if scenario not in SCENARIOS:
        raise ValueError("Unknown demo scenario")
    if scenario == "Domain & DNS":
        return demo_domain_telemetry()
    ip = "203.0.113.42"  # Documentation-only address; never queried.
    malicious = 8 if scenario == "Vendor flags" else 0
    suspicious = 2 if malicious else 0
    date = datetime.now(timezone.utc) - timedelta(days=60 if scenario == "Outdated analysis" else 1)
    vendors = {
        f"Demo vendor {index + 1:02}": {
            "category": "malicious" if index < malicious else "suspicious",
            "result": "Synthetic demo classification",
        }
        for index in range(malicious + suspicious)
    }
    vt = _result("success", "Synthetic report.", _normalize_vt({"data": {
        "id": ip, "type": "ip_address", "attributes": {
            "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                    "harmless": 42, "undetected": 18, "timeout": 0},
            "last_analysis_date": int(date.timestamp()),
            "last_analysis_results": vendors,
            "country": "DE", "asn": 64500, "as_owner": "Example Lab Network",
            "reputation": -12 if malicious else 0,
        },
    }}, ip))
    shodan = _result("success", "Synthetic report.", _normalize_shodan({
        "ip": ip, "ports": [22, 80, 443, 3389], "vulns": ["CVE-DEMO-0001"],
        "tags": ["vpn"], "hostnames": ["host.example.invalid"],
    }, ip))
    if scenario == "Partial intelligence":
        vt = _result("rate_limited", "Synthetic VirusTotal quota response. Try again later.")
    elif scenario == "No intelligence":
        vt = _result("no_data", "Synthetic missing VirusTotal record.")
        shodan = _result("error", "Synthetic Shodan timeout.")
    return {"ip": ip, "indicator": ip, "indicator_type": "ipv4",
            "collected_at": utc_now(), "mode": "demo", "scenario": scenario,
            "sources": {"virustotal": vt, "shodan": shodan}}


def demo_domain_telemetry():
    report = demo_telemetry("Vendor flags")
    domain = "portal.example.invalid"
    report.pop("ip")
    report.update(indicator=domain, indicator_type="domain", scenario="Domain & DNS")
    report["sources"].pop("shodan")
    vt_data = report["sources"]["virustotal"]["data"]
    vt_data.update(registrar="Example Registrar", creation_date=1704067200,
                   country=None, as_owner=None, asn=None)
    values = {"A": "203.0.113.42", "AAAA": "2001:db8::42", "CNAME": "edge.example.invalid.",
              "MX": "10 mail.example.invalid.", "NS": "ns1.example.invalid.", "TXT": '"v=spf1 -all"'}
    # The alias and terminal records belong to different owners.
    records = [{"name": domain if kind == "CNAME" else "edge.example.invalid",
                "type": kind, "value": value, "ttl": 300} for kind, value in values.items()]
    queries = {kind: {"status": "success", "message": "Synthetic DNS answer.", "rcode": 0,
                      "dnssec_validated": False, "queried_at": utc_now(), "cache_hit": False,
                      "records": [record]} for kind, record in zip(values, records)}
    report["sources"]["dns"] = _result("success", "Synthetic DNS snapshot.", {
        "resolver": "Google Public DNS (DoH) — synthetic", "records": records, "queries": queries,
        "resolved_ipv4": ["203.0.113.42"], "resolved_ipv6": ["2001:db8::42"],
    })
    return report
