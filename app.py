import re
import streamlit as st
from scanner import fetch_ip_data, evaluate_risk

st.set_page_config(
    page_title="SOC L1 Triage Assistant",
    page_icon=":3",
    layout="wide"
)



def is_valid_ipv4(ip: str) -> bool:
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(pattern, ip))


st.title("SOC Tier-1 IP Triage Assistant")
st.caption("Automated Open-Source Threat Intelligence (OSINT) Enrichment & Risk Scoring")

with st.sidebar:
    st.header("About Tool")
    st.write(
        "This tool automates initial IPv4 triage for SOC Tier-1 analysts by querying "
        "**Shodan InternetDB** and **IP-API** without requiring API keys."
    )
    st.divider()
    st.subheader("Sample Test IPs")
    st.code("45.33.32.156", language=None)
    st.caption("Nmap Test Server (Open ports)")
    st.code("185.220.101.5", language=None)
    st.caption("Known Tor Exit Node (High Risk)")
    st.code("8.8.8.8", language=None)
    st.caption("Google Public DNS")

col_input, col_btn = st.columns([3, 1])
with col_input:
    target_ip = st.text_input("Enter IPv4 Address for Triage:", placeholder="e.g., 185.220.101.5")
with col_btn:
    st.write("")
    analyze_clicked = st.button("Run Triage", type="primary", use_container_width=True)

if analyze_clicked:
    clean_ip = target_ip.strip()

    if not clean_ip:
        st.warning("Please enter an IPv4 address.")
    elif not is_valid_ipv4(clean_ip):
        st.error("Invalid IPv4 format. Please enter a valid address (e.g., 192.0.2.1).")
    else:
        with st.spinner(f"Collecting telemetry for {clean_ip}..."):
            raw_data = fetch_ip_data(clean_ip)
            report = evaluate_risk(raw_data)

        if report.get("error"):
            st.error(f"Telemetry error: {report['error']}")
        else:
            st.divider()

            verdict = report["verdict"]
            score = report["risk_score"]

            if score >= 60:
                st.error(f"**VERDICT: {verdict}** (Risk Score: {score}/100)")
            elif score >= 30:
                st.warning(f"**VERDICT: {verdict}** (Risk Score: {score}/100)")
            else:
                st.success(f"**VERDICT: {verdict}** (Risk Score: {score}/100)")

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Risk Score", f"{score} / 100")
            m2.metric("Location", f"{report['country']} ({report['city']})")
            m3.metric("Open Ports", len(report["ports"]))
            m4.metric("Known CVEs", len(report["vulns"]))

            st.divider()

            left_col, right_col = st.columns(2)

            with left_col:
                st.subheader("Risk Factors & Network Info")
                st.markdown(f"**ISP / Organization:** `{report['isp']}` ({report['org']})")
                st.markdown(f"**Hosting / VPN / Proxy:** `{'Yes' if report['is_proxy_or_hosting'] else 'No'}`")
                st.markdown(f"**Hostnames:** `{', '.join(report['hostnames']) if report['hostnames'] else 'None'}`")

                st.markdown("**Triggered Risk Rules:**")
                for reason in report["risk_reasons"]:
                    st.markdown(f"- {reason}")

            with right_col:
                st.subheader("Attack Surface (Shodan)")
                st.markdown(f"**Exposed Ports:** `{report['ports'] if report['ports'] else 'None detected'}`")
                st.markdown(f"**Threat Tags:** `{report['tags'] if report['tags'] else 'None'}`")

                if report["vulns"]:
                    st.markdown("**Detected Vulnerabilities (CVEs):**")
                    st.code(", ".join(report["vulns"][:10]))
                else:
                    st.markdown("**Detected Vulnerabilities (CVEs):** `None`")

            st.divider()

            st.subheader("📋 Copy-Paste SOC Ticket Note")
            ticket_note = f"""### [SOC L1 Triage] Automated IP Enrichment
- **Target IP:** `{report['ip']}`
- **Verdict:** **{verdict}** (Score: {score}/100)
- **Geo / ISP:** {report['country']}, {report['city']} | {report['isp']}
- **Hosting/Proxy:** {report['is_proxy_or_hosting']}
- **Open Ports:** {report['ports'] if report['ports'] else 'None'}
- **Tags:** {report['tags'] if report['tags'] else 'None'}
- **CVEs Count:** {len(report['vulns'])}
- **Key Findings:** {'; '.join(report['risk_reasons'])}
"""
            st.code(ticket_note, language="markdown")

            with st.expander("View Raw Telemetry JSON"):
                st.json(report)