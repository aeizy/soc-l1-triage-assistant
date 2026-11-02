"""DNS snapshots via Google Public DNS over HTTPS, with per-query TTL caching."""
from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import threading
import time

import requests

from indicators import validate_domain

RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16}
TYPE_NAMES = {value: key for key, value in RECORD_TYPES.items()}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _query_result(status, message, **extra):
    return {"status": status, "message": message, "queried_at": _now(),
            "cache_hit": False, "records": [], "rcode": None,
            "dnssec_validated": None, **extra}


def normalize_answer(payload, domain, record_type):
    if not isinstance(payload, dict) or type(payload.get("Status")) is not int:
        raise ValueError("Invalid DNS response")
    questions = payload.get("Question", [])
    if not isinstance(questions, list) or not any(
        isinstance(q, dict) and q.get("name", "").lower().rstrip(".") == domain
        and q.get("type") == RECORD_TYPES[record_type] for q in questions
    ):
        raise ValueError("DNS response does not match the query")
    rcode = payload["Status"]
    if payload.get("TC"):
        return _query_result("error", "Truncated DNS response; records were not used.", rcode=rcode)
    if rcode == 3:
        return _query_result("no_data", "NXDOMAIN: the resolver reports that this name does not exist.", rcode=rcode)
    if rcode != 0:
        return _query_result("error", f"DNS resolver returned RCODE {rcode} (2 means SERVFAIL).", rcode=rcode)
    answers = payload.get("Answer", [])
    if not isinstance(answers, list):
        raise ValueError("Invalid answer section")
    records = []
    for answer in answers:
        if not isinstance(answer, dict):
            raise ValueError("Invalid record")
        if type(answer.get("type")) is not int or answer["type"] not in TYPE_NAMES:
            continue  # Ignore additional DNSSEC / unsupported record types.
        name, value, ttl = answer.get("name"), answer.get("data"), answer.get("TTL")
        if not isinstance(name, str) or not name or not isinstance(value, str) or type(ttl) is not int or ttl < 0:
            raise ValueError("Incomplete DNS record")
        if answer["type"] == 1:
            value = str(ipaddress.IPv4Address(value))
        elif answer["type"] == 28:
            value = str(ipaddress.IPv6Address(value))
        records.append({"name": name.rstrip("."), "type": TYPE_NAMES[answer["type"]], "value": value, "ttl": ttl})
    ad = payload.get("AD")
    matching = any(record["type"] == record_type for record in records)
    # A CNAME chain can be useful even when the requested terminal record is absent.
    return _query_result("success" if records else "no_data",
                         "DNS answer received." if matching else "No requested record; any returned aliases are shown.",
                         records=records, rcode=rcode, dnssec_validated=ad if type(ad) is bool else None)


class DNSClient:
    def __init__(self, session=None):
        self._session = session or requests.Session()
        self._cache = {}
        self._lock = threading.Lock()

    def query(self, domain, record_type):
        domain = validate_domain(domain)
        if record_type not in RECORD_TYPES:
            raise ValueError("Unsupported DNS record type")
        with self._lock:
            cached = self._cache.get((domain, record_type))
            if cached and time.monotonic() < cached[0]:
                result = deepcopy(cached[1])
                result["cache_hit"] = True
                return result
            try:
                response = self._session.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": record_type, "edns_client_subnet": "0.0.0.0/0"},
                    headers={"Accept": "application/dns-json"}, timeout=(2, 4), allow_redirects=False,
                )
                if response.status_code == 429:
                    return _query_result("rate_limited", "DNS resolver rate limit reached; try again later.")
                if response.status_code != 200:
                    return _query_result("error", f"DNS resolver returned HTTP {response.status_code}.")
                result = normalize_answer(response.json(), domain, record_type)
            except requests.Timeout:
                return _query_result("error", "DNS resolver timed out.")
            except requests.exceptions.JSONDecodeError:
                return _query_result("error", "DNS resolver returned invalid JSON.")
            except requests.RequestException:
                return _query_result("error", "Unable to reach the DNS resolver.")
            except (ValueError, TypeError, KeyError, AttributeError):
                return _query_result("error", "DNS resolver returned an invalid response.")
            ttl = min((record["ttl"] for record in result["records"]), default=0)
            ttl = min(ttl, 300)
            if result["status"] == "success" and ttl > 0:
                self._cache[(domain, record_type)] = (time.monotonic() + ttl, deepcopy(result))
            return result

    def resolve(self, domain):
        domain = validate_domain(domain)
        queries = {kind: self.query(domain, kind) for kind in RECORD_TYPES}
        records = {}
        for query in queries.values():
            for record in query["records"]:
                key = (record["name"], record["type"], record["value"])
                if key not in records or record["ttl"] < records[key]["ttl"]:
                    records[key] = record
        errors = sum(q["status"] in ("error", "rate_limited") for q in queries.values())
        status = "error" if errors == len(queries) else "partial" if errors else "success" if records else "no_data"
        rows = sorted(records.values(), key=lambda r: (r["type"], r["name"], r["value"]))
        return {
            "status": status, "message": f"{len(rows)} DNS records; {errors} failed query types.",
            "queried_at": min(q["queried_at"] for q in queries.values()),
            "cache_hit": all(q["cache_hit"] for q in queries.values()),
            "data": {"resolver": "Google Public DNS (DoH)", "records": rows, "queries": queries,
                     "resolved_ipv4": sorted({r["value"] for r in rows if r["type"] == "A"}),
                     "resolved_ipv6": sorted({r["value"] for r in rows if r["type"] == "AAAA"})},
        }
