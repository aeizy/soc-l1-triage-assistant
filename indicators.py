"""Normalize public IPv4 addresses and fully qualified domain names."""
import ipaddress
import re


def validate_ip(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value.strip())
    except (ipaddress.AddressValueError, AttributeError) as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc
    if not address.is_global or address.is_multicast:
        raise ValueError("Only public unicast IPv4 addresses can be enriched.")
    return str(address)


def validate_domain(value: str) -> str:
    try:
        domain = value.strip().removesuffix(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, AttributeError) as exc:
        raise ValueError("Enter a valid domain name, for example example.com.") from exc
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ) or labels[-1].isdigit():
        raise ValueError("Enter a domain name without a URL, port or path, for example example.com.")
    if labels[-1] in {"local", "localhost", "internal", "invalid", "test", "example", "onion", "arpa"}:
        raise ValueError("Use a public domain name; local and reserved names are not queried.")
    return domain


def parse_indicator(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a public IPv4 address or domain name.")
    value = value.strip()
    if re.fullmatch(r"[0-9.]+", value):
        return "ipv4", validate_ip(value)
    return "domain", validate_domain(value)
