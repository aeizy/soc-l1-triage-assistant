"""Passive IP/domain enrichment and explainable triage for a personal SOC lab."""

from copy import deepcopy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import os
import threading
import time

import requests

from dns_lookup import DNSClient
from indicators import parse_indicator, validate_ip

POLICY_VERSION = "2.0"
VT_INTERVAL_SECONDS = 16
VT_DAILY_LIMIT = 500
STALE_AFTER_DAYS = 30
STAT_FIELDS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _result(status, message, data=None, **extra):
    return {
        "status": status, "message": message, "queried_at": utc_now(),
        "cache_hit": False, "data": data or {}, **extra,
    }


def _strings(value):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("Expected a list of strings")
    return sorted(set(value))


def _normalize_shodan(payload, ip):
    if not isinstance(payload, dict) or payload.get("ip") != ip:
        raise ValueError("Unexpected Shodan response")
    ports = payload["ports"]
    if not isinstance(ports, list) or any(
        type(port) is not int or not 1 <= port <= 65535 for port in ports
    ):
        raise ValueError("Invalid ports")
    return {
        "ports": sorted(set(ports)), "vulns": _strings(payload.get("vulns", [])),
        "tags": _strings(payload.get("tags", [])),
        "hostnames": _strings(payload.get("hostnames", [])),
    }


def _normalize_vt(payload, ip, indicator_type="ipv4"):
    obj = payload["data"]
    if obj.get("id") != ip or obj.get("type") != ("domain" if indicator_type == "domain" else "ip_address"):
        raise ValueError("Unexpected VirusTotal object")
    attrs = obj["attributes"]
    if not isinstance(attrs, dict):
        raise ValueError("Invalid attributes")
    raw_stats = attrs.get("last_analysis_stats")
    stats = None
    if raw_stats is not None:
        if not isinstance(raw_stats, dict) or not all(
            key in raw_stats and type(raw_stats[key]) is int and raw_stats[key] >= 0
            for key in ("malicious", "suspicious", "harmless", "undetected")
        ):
            raise ValueError("Incomplete analysis counts")
        stats = {key: raw_stats.get(key, 0) for key in STAT_FIELDS}
        if any(type(value) is not int or value < 0 for value in stats.values()):
            raise ValueError("Invalid analysis counts")
    analysis_date = attrs.get("last_analysis_date")
    if type(analysis_date) is not int or not 0 < analysis_date <= time.time() + 300:
        analysis_date = None
    engines = []
    results = attrs.get("last_analysis_results", {})
    if isinstance(results, dict):
        for name, item in sorted(results.items()):
            if isinstance(item, dict) and item.get("category") in ("malicious", "suspicious"):
                engines.append({
                    "vendor": str(name), "category": item["category"],
                    "result": str(item.get("result") or "Unspecified"),
                })
    return {
        "stats": stats,
        "has_analysis": bool(stats and sum(stats[key] for key in STAT_FIELDS[:4])),
        "last_analysis_date": analysis_date,
        "country": attrs.get("country") if isinstance(attrs.get("country"), str) else None,
        "as_owner": attrs.get("as_owner") if isinstance(attrs.get("as_owner"), str) else None,
        "asn": attrs.get("asn") if type(attrs.get("asn")) is int else None,
        "reputation": attrs.get("reputation") if type(attrs.get("reputation")) is int else None,
        "flagged_vendors": engines,
        "registrar": attrs.get("registrar") if isinstance(attrs.get("registrar"), str) else None,
        "creation_date": attrs.get("creation_date") if type(attrs.get("creation_date")) is int and 0 < attrs["creation_date"] <= time.time() else None,
    }


class EnrichmentClient:
    """In-memory cache and VT quota guard for one app process / API key.

    The key is sent only in the VT header, never in a report or URL.
    The process-local guard cannot account for use in other applications.
    """

    def __init__(self, vt_api_key=None, session=None):
        self._vt_key = (vt_api_key or "").strip()
        self._session = session or requests.Session()
        self._dns = DNSClient(self._session)
        self._cache = {}
        self._lock = threading.Lock()
        self._vt_next_request = 0.0
        self._vt_day = None
        self._vt_requests = 0

    def _retry_seconds(self, response):
        value = response.headers.get("Retry-After", "60")
        try:
            seconds = int(value)
        except (ValueError, TypeError):
            try:
                seconds = int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                seconds = 60
        return max(VT_INTERVAL_SECONDS, min(seconds, 86400))

    def _lookup(self, provider, ip, indicator_type="ipv4"):
        with self._lock:
            now = time.monotonic()
            cached = self._cache.get((provider, indicator_type, ip))
            if cached and now < cached[0]:
                result = deepcopy(cached[1])
                result["cache_hit"] = True
                return result
            if provider == "virustotal":
                if not self._vt_key:
                    return _result("missing_key", "VirusTotal API key is not configured.")
                today = datetime.now(timezone.utc).date()
                if today != self._vt_day:
                    self._vt_day, self._vt_requests = today, 0
                if self._vt_requests >= VT_DAILY_LIMIT:
                    return _result("rate_limited", "Local daily VirusTotal allowance reached; try after 00:00 UTC.")
                if now < self._vt_next_request:
                    seconds = int(self._vt_next_request - now) + 1
                    return _result("rate_limited", f"VirusTotal cooldown: try again in {seconds}s.", retry_after_seconds=seconds)
                self._vt_next_request = now + VT_INTERVAL_SECONDS
                self._vt_requests += 1
                collection = "domains" if indicator_type == "domain" else "ip_addresses"
                url = f"https://www.virustotal.com/api/v3/{collection}/{ip}"
                headers = {"x-apikey": self._vt_key, "Accept": "application/json"}
                normalizer = lambda payload, value: _normalize_vt(payload, value, indicator_type)
            else:
                url = f"https://internetdb.shodan.io/{ip}"
                headers = {"Accept": "application/json"}
                normalizer = _normalize_shodan
            try:
                response = self._session.get(url, headers=headers, timeout=(3.05, 8), allow_redirects=False)
                code = response.status_code
                if code == 429:
                    seconds = self._retry_seconds(response)
                    if provider == "virustotal":
                        self._vt_next_request = time.monotonic() + seconds
                    return _result("rate_limited", f"Provider quota reached; retry in at least {seconds}s. A daily quota may take longer to reset.", retry_after_seconds=seconds)
                if code in (401, 403):
                    return _result("auth_error", "Provider rejected access. Check the API key and account permissions.")
                if code == 404:
                    result = _result("no_data", "Provider has no record for this indicator; this is not a clean verdict.")
                elif code != 200:
                    return _result("error", f"Provider returned HTTP {code}. No verdict inferred.")
                else:
                    data = normalizer(response.json(), ip)
                    result = _result("success", "Report retrieved.", data)
            except requests.Timeout:
                return _result("error", "Provider timed out. No verdict inferred.")
            except requests.exceptions.JSONDecodeError:
                return _result("error", "Provider returned invalid JSON.")
            except requests.RequestException:
                return _result("error", "Unable to reach provider. No verdict inferred.")
            except (ValueError, KeyError, TypeError, AttributeError):
                return _result("error", "Provider returned an invalid or incomplete response.")
            ttl = (900 if provider == "virustotal" else 3600) if result["status"] == "success" else 300
            result["cache_expires_at"] = datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat(timespec="seconds")
            self._cache[(provider, indicator_type, ip)] = (time.monotonic() + ttl, deepcopy(result))
            return result

    def fetch(self, value):
        kind, indicator = parse_indicator(value)
        sources = {"virustotal": self._lookup("virustotal", indicator, kind)}
        if kind == "domain":
            sources["dns"] = self._dns.resolve(indicator)
        else:
            sources["shodan"] = self._lookup("shodan", indicator)
        return {"indicator": indicator, "indicator_type": kind,
                **({"ip": indicator} if kind == "ipv4" else {}),
                "collected_at": utc_now(), "mode": "live", "sources": sources}


def fetch_ip_data(ip: str, vt_api_key=None, client=None) -> dict:
    client = client or EnrichmentClient(vt_api_key or os.getenv("VT_API_KEY"))
    return client.fetch(ip)


def evaluate_risk(telemetry: dict) -> dict:
    """Prioritize investigation; vendor counts are not an attack probability."""
    report = deepcopy(telemetry)
    vt = report["sources"]["virustotal"]
    shodan = report["sources"].get("shodan")
    dns = report["sources"].get("dns")
    data = vt["data"]
    usable = vt["status"] == "success" and data.get("has_analysis", False)
    available = sum(source["status"] in ("success", "partial") for source in report["sources"].values())
    complete = all(source["status"] == "success" for source in report["sources"].values())
    coverage = "FULL" if complete and usable else "PARTIAL" if available else "UNAVAILABLE"
    reasons, warnings, context = [], [], []
    for name, source in report["sources"].items():
        if source["status"] != "success":
            warnings.append(f"{name}: {source['message']}")
    score, priority, assessment = None, "UNASSESSED", "INSUFFICIENT DATA"
    freshness = "UNKNOWN"
    if usable:
        stats = data["stats"]
        malicious, suspicious = stats["malicious"], stats["suspicious"]
        score = 70 if malicious >= 5 else 45 if malicious >= 2 else 25 if malicious == 1 else 0
        if suspicious:
            score += 15
        reasons.append(f"VirusTotal: {malicious} malicious and {suspicious} suspicious vendor classifications.")
        timestamp = data.get("last_analysis_date")
        if timestamp:
            age = max(0, (time.time() - timestamp) / 86400)
            freshness = "STALE" if age > STALE_AFTER_DAYS else "RECENT"
        if freshness != "RECENT":
            warnings.append("VirusTotal analysis is older than 30 days or its age is unknown. Verify current activity.")
        priority = "HIGH" if score >= 70 else "MEDIUM" if score >= 15 else "LOW"
        assessment = "VENDOR FLAGS PRESENT" if score else "NO VENDOR FLAGS"
        if score == 0 and freshness != "RECENT":
            score, priority, assessment = None, "UNASSESSED", "FRESH DATA REQUIRED"
    elif vt["status"] == "success":
        warnings.append("VirusTotal returned metadata without usable vendor classifications.")
    if not usable:
        reasons.append("No usable VirusTotal vendor analysis; priority cannot be assessed.")
    if shodan and shodan["status"] == "success":
        surface = shodan["data"]
        context.append(f"Shodan observed {len(surface['ports'])} open ports and {len(surface['vulns'])} potential CVEs.")
        if surface["tags"]:
            context.append("Shodan tags: " + ", ".join(surface["tags"]) + ".")
        context.append("Ports, CVEs and infrastructure tags do not add priority points. Validate exposure in the alert context.")
    if dns:
        context.append(f"DNS snapshot: {len(dns['data']['records'])} records from Google Public DNS over HTTPS.")
        context.append("DNS records and registration age add no priority points. Shared hosting IPs do not establish domain reputation.")
        if dns["status"] == "partial":
            warnings.append("Some DNS query types failed; review the per-type status before drawing conclusions.")
    warnings.append("No vendor flags or missing records do not establish that an indicator is safe.")
    if priority == "HIGH":
        action = "Review the original alert and related logs promptly. Escalate if the activity and asset context support an incident."
    elif priority == "MEDIUM":
        action = "Validate the vendor flags against event timing, destination, account activity and approved services."
    elif priority == "LOW":
        action = "Continue triage using the alert evidence. Do not close an alert solely because reputation checks have no flags."
    else:
        action = "Resolve missing or outdated intelligence and investigate the original alert before making a disposition."
    report.update({
        "policy_version": POLICY_VERSION, "priority_score": score, "priority": priority,
        "assessment": assessment, "coverage": coverage, "vt_freshness": freshness,
        "reasons": reasons, "context": context, "warnings": warnings,
        "recommended_action": action,
    })
    return report


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Passive IP and DNS enrichment for a personal SOC lab")
    parser.add_argument("indicator", help="Public IPv4 address or domain name")
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate_risk(fetch_ip_data(args.indicator)), indent=2))
    except ValueError as exc:
        parser.error(str(exc))
