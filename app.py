"""Minimal Streamlit workspace for passive IP and domain triage."""
import json
import os

import streamlit as st

from demo import SCENARIOS, demo_telemetry
from reporting import build_ticket_note, format_timestamp
from indicators import parse_indicator
from scanner import EnrichmentClient, evaluate_risk

st.set_page_config(page_title="IOC Triage | SOC Workspace", layout="wide")

st.markdown("""
<style>
.block-container { max-width: 1180px; padding-top: 2.7rem; padding-bottom: 3rem; }
h1 { font-size: 2.35rem !important; font-weight: 600 !important; letter-spacing: -.065rem; }
h2 { font-size: 1.2rem !important; font-weight: 550 !important; }
h3 { font-size: 1rem !important; font-weight: 550 !important; }
p, li { line-height: 1.55; }
.eyebrow { color: #AFAFAF; font-size: .72rem; font-weight: 600; letter-spacing: .16em; margin-bottom: .65rem; }
.brand { font-size: 1.3rem; font-weight: 600; letter-spacing: -.02em; color: #E6E6E6; }
.priority { display: inline-block; font-size: .75rem; letter-spacing: .09em; font-weight: 600; padding: .3rem .65rem; border: 1px solid; border-radius: .3rem; }
.priority-high { color: #000000; background: #D9D9D9; border-color: #D9D9D9; }
.priority-medium { color: #E6E6E6; background: #262626; border-color: #777777; }
.priority-low { color: #BFBFBF; background: #111111; border-color: #4D4D4D; }
.priority-unassessed { color: #AFAFAF; background: #111111; border-color: #333333; border-style: dashed; }
[data-testid="stMetricValue"] { font-size: 1.7rem; font-weight: 500; }
[data-testid="stMetricLabel"] { color: #B3B3B3; font-size: .78rem; }
[data-testid="stSidebar"] .block-container { padding-top: 2rem; }
[data-testid="stForm"] { padding: 1.05rem 1.15rem; }
[data-testid="stBaseButton-primary"], [data-testid="stBaseButton-primaryFormSubmit"],
[data-testid="stBaseButton-primaryFormSubmit"] p { color: #000000 !important; font-weight: 600; }
[data-testid="stAlert"] { background: #161616; border: 1px solid #444444; }
[data-testid="stAlert"] * { color: #D9D9D9 !important; }
[data-testid="stVerticalBlockBorderWrapper"] { box-shadow: none; }
#MainMenu, footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


def configured_key():
    key = os.getenv("VT_API_KEY", "").strip()
    if key:
        return key
    try:
        return str(st.secrets.get("VT_API_KEY", "")).strip()
    except (FileNotFoundError, st.errors.StreamlitSecretNotFoundError):
        return ""


@st.cache_resource(show_spinner=False)
def shared_client(api_key):
    # Shared across reruns and sessions using this key; quotas remain process-local.
    return EnrichmentClient(api_key)


key = configured_key()
with st.sidebar:
    st.markdown('<div class="eyebrow">SOC WORKSPACE</div><div class="brand">IOC Triage</div>', unsafe_allow_html=True)
    st.caption("Passive intelligence. Clear evidence.")
    st.divider()
    mode = st.radio("Workspace mode", ["Demo", "Live"], horizontal=True)
    scenario = st.selectbox("Scenario", list(SCENARIOS)) if mode == "Demo" else None
    if scenario:
        st.caption(SCENARIOS[scenario])
    st.divider()
    st.markdown("**Intelligence sources**")
    st.caption("VirusTotal · vendor classifications")
    st.caption("Shodan InternetDB · exposed services")
    st.caption("Google Public DNS · DNS records")
    st.caption("VirusTotal key: " + ("configured" if key else "not configured"))
    with st.expander("API setup"):
        st.write("Set VT_API_KEY in your environment or in .streamlit/secrets.toml, then restart the app.")
        st.code('VT_API_KEY = "your-key-here"', language="toml")
        st.caption("The same VT key supports IP and domain reports. Shodan InternetDB and Google Public DNS require no key.")
    st.divider()
    st.markdown("**Analysis policy**")
    st.caption("Vendor flags set investigation priority. Exposure remains supporting context.")
    st.caption("Score is a heuristic, not an attack probability.")
    with st.expander("Scoring rules"):
        st.write("Malicious classifications: 1 → 25 points; 2–4 → 45; 5+ → 70. Any suspicious classification adds 15.")
        st.write("Low: 0–14 · Medium: 15–69 · High: 70–100. Missing usable analysis means unassessed.")
        st.write("Old or undated reports without flags require fresh data. Ports, CVEs and infrastructure tags add no points.")
    st.caption("Personal lab / portfolio · Policy 2.0")

st.markdown('<div class="eyebrow">INDICATOR INVESTIGATION</div>', unsafe_allow_html=True)
st.title("A clearer first look at an indicator.")
st.caption("Investigate IP addresses and domains with vendor intelligence, DNS records and service context.")

active = (mode, scenario)
if st.session_state.get("active_workspace") != active:
    st.session_state["active_workspace"] = active
    st.session_state.pop("report", None)
    if mode == "Demo":
        st.session_state["report"] = evaluate_risk(demo_telemetry(scenario))

if mode == "Demo":
    st.caption("DEMO DATA · Synthetic indicators and vendor results. No external requests.")
else:
    st.caption("LIVE LOOKUP · IP → VirusTotal + Shodan. Domain → VirusTotal + Google Public DNS. Enter a name without https:// or a path.")
    if not key:
        st.warning("VirusTotal key is missing. DNS and Shodan enrichment remain available; priority will be unassessed.")

with st.form("triage_form"):
    input_col, button_col = st.columns([4, 1], vertical_alignment="bottom")
    with input_col:
        demo_value = "portal.example.invalid" if scenario == "Domain & DNS" else "203.0.113.42"
        target_ip = st.text_input("IP address or domain", value=demo_value if mode == "Demo" else "",
                                  placeholder="8.8.8.8 or example.com", disabled=mode == "Demo")
    with button_col:
        submitted = st.form_submit_button("Run triage", type="primary", width="stretch")
    st.caption("VT cache 15 min · Shodan cache 60 min · DNS cache respects record TTL (max 5 min)")

if submitted:
    st.session_state.pop("report", None)
    try:
        if mode == "Demo":
            telemetry = demo_telemetry(scenario)
        else:
            _, clean_ip = parse_indicator(target_ip)
            with st.spinner("Retrieving source reports..."):
                telemetry = shared_client(key).fetch(clean_ip)
        st.session_state["report"] = evaluate_risk(telemetry)
    except ValueError as exc:
        st.error(str(exc))

report = st.session_state.get("report")
if report is None:
    st.write("")
    st.subheader("Start with an indicator")
    st.caption("Enter a public IPv4 address or domain name. Source gaps remain visible in the result.")
    st.stop()

st.divider()
title_col, badge_col = st.columns([4, 1], vertical_alignment="center")
with title_col:
    indicator = report.get("indicator", report.get("ip"))
    st.subheader(indicator + " / Investigation summary")
    st.caption("Synthetic report" if report["mode"] == "demo" else "Collected " + report["collected_at"])
with badge_col:
    priority = report["priority"]  # Fixed policy enum; no external HTML.
    st.markdown(f'<span class="priority priority-{priority.lower()}">{priority}</span>', unsafe_allow_html=True)

vt = report["sources"]["virustotal"]
shodan = report["sources"].get("shodan")
dns = report["sources"].get("dns")
stats = vt["data"].get("stats")
surface = shodan["data"] if shodan and shodan["status"] == "success" else None
usable_stats = stats if vt["data"].get("has_analysis") and vt["status"] == "success" else None
counts = st.columns(4)
score = report["priority_score"]
counts[0].metric("Investigation score", f"{score} / 100" if score is not None else "Not assessed")
counts[1].metric("Malicious / suspicious", f"{stats['malicious']} / {stats['suspicious']}" if usable_stats else "Unavailable")
if dns:
    counts[2].metric("DNS records", len(dns["data"]["records"]) if dns["status"] != "error" else "Unavailable")
    counts[3].metric("Resolved IPs", len(dns["data"]["resolved_ipv4"]) + len(dns["data"]["resolved_ipv6"]) if dns["status"] != "error" else "Unavailable")
else:
    counts[2].metric("Observed ports", len(surface["ports"]) if surface is not None else "Unavailable")
    counts[3].metric("Potential CVEs", len(surface["vulns"]) if surface is not None else "Unavailable")
st.caption(f"{report['assessment']} · Source coverage: {report['coverage'].lower()} · VT analysis age: {report['vt_freshness'].lower()}")

for name, col in zip(report["sources"], st.columns(len(report["sources"]))):
    source = report["sources"][name]
    with col.container(border=True):
        st.markdown("**" + {"virustotal": "VirusTotal", "shodan": "Shodan InternetDB", "dns": "Google Public DNS"}[name] + "**")
        st.caption(source["status"].replace("_", " ").upper() + (" · CACHED" if source["cache_hit"] else ""))
        if name == "virustotal":
            st.caption("Last analysis: " + format_timestamp(source["data"].get("last_analysis_date")))
        elif name == "shodan":
            st.caption("Weekly dataset · Potential CVEs inferred from service metadata")
        else:
            st.caption("DNS over HTTPS · A / AAAA / CNAME / MX / NS / TXT")
        st.caption("Retrieved: " + source["queried_at"])
        if source["status"] != "success":
            st.write(source["message"])

panels = st.tabs(["Evidence & next steps"] + (["DNS records"] if dns else []) + ["Report & export"])
evidence_tab, export_tab = panels[0], panels[-1]
dns_tab = panels[1] if dns else None
with evidence_tab:
    left, right = st.columns([1.1, 1], gap="large")
    with left:
        st.subheader("Why this priority")
        for reason in report["reasons"]:
            st.write(reason)
        st.subheader("Recommended next step")
        st.write(report["recommended_action"])
        st.subheader("Data limitations")
        for warning in report["warnings"]:
            st.caption(warning)
        if vt["data"].get("flagged_vendors"):
            st.subheader("Flagged vendor results")
            st.dataframe(vt["data"]["flagged_vendors"], hide_index=True, width="stretch")
    with right:
        st.subheader("Domain context" if dns else "Network context")
        if dns:
            st.text("Registrar: " + (vt["data"].get("registrar") or "Unavailable"))
            st.caption("Created: " + format_timestamp(vt["data"].get("creation_date")))
            st.caption("Resolved IPv4 / IPv6")
            st.text("\n".join(dns["data"]["resolved_ipv4"] + dns["data"]["resolved_ipv6"]) or "No address records available")
        else:
            owner = vt["data"].get("as_owner") or "Unavailable"
            asn = vt["data"].get("asn")
            st.write(owner + (f" · AS{asn}" if asn is not None else ""))
            st.caption("Country: " + (vt["data"].get("country") or "Unavailable"))
        reputation = vt["data"].get("reputation")
        st.caption("VT community reputation: " + (str(reputation) if reputation is not None else "Unavailable") + " · not included in score")
        if dns:
            st.caption("DNS records are a point-in-time snapshot. Investigate a resolved public IPv4 separately to view Shodan services.")
        else:
            st.subheader("Service exposure")
        if shodan and surface is None:
            st.write("Shodan exposure data is unavailable.")
        elif surface is not None:
            st.caption("Observed ports")
            st.code(", ".join(map(str, surface["ports"])) or "None reported", language=None)
            st.caption("Infrastructure tags")
            st.text(", ".join(surface["tags"]) or "None reported")
            st.caption("Hostnames")
            st.text(", ".join(surface["hostnames"]) or "None reported")
            if surface["vulns"]:
                with st.expander(f"Potential CVEs ({len(surface['vulns'])})"):
                    st.text("\n".join(surface["vulns"]))
        if shodan:
            st.caption("Exposure describes services, not malicious activity.")
        if report["mode"] == "live":
            links = st.columns(2)
            vt_kind = "domain" if dns else "ip-address"
            links[0].link_button("VirusTotal report", f"https://www.virustotal.com/gui/{vt_kind}/{indicator}")
            if shodan:
                links[1].link_button("Shodan record", f"https://www.shodan.io/host/{indicator}")

if dns:
    with dns_tab:
        st.subheader("DNS records")
        st.caption("TTL is the resolver's value at retrieval. The same IP can serve many unrelated domains.")
        if dns["data"]["records"]:
            st.dataframe(dns["data"]["records"], hide_index=True, width="stretch")
        else:
            st.write("No DNS records available. Review query statuses below.")
        with st.expander("DNS query status"):
            st.dataframe([
                {"type": kind, "status": query["status"], "rcode": query["rcode"],
                 "DNSSEC AD": query["dnssec_validated"], "cached": query["cache_hit"],
                 "retrieved": query["queried_at"], "detail": query["message"]}
                for kind, query in dns["data"]["queries"].items()
            ], hide_index=True, width="stretch")
            st.caption("AD=true means the resolver validated that answer with DNSSEC. AD=false alone does not mean validation failed or that the domain is malicious.")

with export_tab:
    note = build_ticket_note(report)
    st.caption("Review the evidence and add your disposition before using this note in a ticket.")
    st.code(note, language="markdown", wrap_lines=True)
    md_col, json_col = st.columns(2)
    prefix = ("demo-" if report["mode"] == "demo" else "") + "triage-" + indicator
    md_col.download_button("Download Markdown", note, file_name=prefix + ".md", mime="text/markdown", on_click="ignore", width="stretch")
    json_col.download_button("Download JSON", json.dumps(report, indent=2), file_name=prefix + ".json", mime="application/json", on_click="ignore", width="stretch")
    with st.expander("Normalized source data"):
        st.json(report)
