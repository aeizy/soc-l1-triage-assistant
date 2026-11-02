"""Portable notes that keep data gaps and source age visible."""

from datetime import datetime, timezone


def format_timestamp(value):
    if not value:
        return "Unknown"
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OverflowError, OSError, TypeError):
        return "Unknown"


def build_ticket_note(report):
    score = report["priority_score"]
    vt = report["sources"]["virustotal"]
    shodan = report["sources"].get("shodan")
    dns = report["sources"].get("dns")
    indicator = report.get("indicator", report.get("ip"))
    stats = vt["data"].get("stats")
    surface = shodan["data"] if shodan and shodan["status"] == "success" else None
    lines = [
        "## SOC L1 | Indicator enrichment",
        f"- Mode: {report['mode'].upper()}" + (" — SYNTHETIC DATA" if report["mode"] == "demo" else ""),
        f"- Indicator: {indicator} ({report.get('indicator_type', 'ipv4')})",
        f"- Collected at: {report['collected_at']}",
        f"- Investigation priority: {report['priority']}",
        f"- Heuristic score: {str(score) + '/100' if score is not None else 'Not assessed'} (policy {report['policy_version']}; not a probability)",
        f"- Assessment: {report['assessment']}",
        f"- Source coverage: {report['coverage']}",
        f"- VT analysis date: {format_timestamp(vt['data'].get('last_analysis_date'))} ({report['vt_freshness']})",
    ]
    for name, source in report["sources"].items():
        lines.append(f"- {name}: {source['status']} | fetched {source['queried_at']} | cached: {source['cache_hit']} | {source['message']}")
    if stats:
        lines.append(f"- VT vendor classifications: {stats['malicious']} malicious / {stats['suspicious']} suspicious / {stats['harmless']} harmless / {stats['undetected']} undetected / {stats['timeout']} timeout")
    if surface is not None:
        lines.extend([
            f"- Shodan observed ports: {', '.join(map(str, surface['ports'])) or 'None reported'}",
            f"- Shodan potential CVEs: {', '.join(surface['vulns']) or 'None reported'}",
            f"- Shodan tags: {', '.join(surface['tags']) or 'None reported'}",
        ])
    if dns:
        lines.extend(["", "### DNS snapshot", f"- Resolver: {dns['data']['resolver']}"])
        for kind, query in dns["data"]["queries"].items():
            lines.append(f"- {kind}: {query['status']} | RCODE {query['rcode']} | {query['message']}")
        for record in dns["data"]["records"]:
            lines.append(f"- {record['name']} | {record['type']} | {record['value']} | TTL {record['ttl']}s at retrieval")
        lines.extend([f"- Registrar (VT): {vt['data'].get('registrar') or 'Unknown'}",
                      f"- Creation date (VT): {format_timestamp(vt['data'].get('creation_date'))}",
                      "- DNS resolution is a point-in-time snapshot; absent records and DNSSEC AD=false do not establish maliciousness."])
    lines.extend(["", "### Findings", *[f"- {item}" for item in report["reasons"] + report["context"]],
                  "", "### Limitations", *[f"- {item}" for item in report["warnings"]],
                  *(["- Shodan InternetDB is updated weekly; potential CVEs are inferred from service metadata."] if shodan else []),
                  "", "### Next step", report["recommended_action"], "",
                  "### Analyst disposition", "Pending manual review of the original alert and event evidence."])
    return "\n".join(lines) + "\n"
