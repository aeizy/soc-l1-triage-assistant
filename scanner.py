import requests


def fetch_ip_data(ip: str) -> dict:

    telemetry = {
        "ip": ip,
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "is_proxy_or_hosting": False,
        "ports": [],
        "vulns": [],
        "tags": [],
        "hostnames": [],
        "error": None
    }

    try:
        geo_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,proxy,hosting"
        geo_response = requests.get(geo_url, timeout=5).json()

        if geo_response.get("status") == "success":
            telemetry["country"] = geo_response.get("country", "Unknown")
            telemetry["city"] = geo_response.get("city", "Unknown")
            telemetry["isp"] = geo_response.get("isp", "Unknown")
            telemetry["org"] = geo_response.get("org", "Unknown")
            telemetry["is_proxy_or_hosting"] = (
                geo_response.get("proxy", False) or geo_response.get("hosting", False)
            )

        shodan_url = f"https://internetdb.shodan.io/{ip}"
        shodan_response = requests.get(shodan_url, timeout=5)

        if shodan_response.status_code == 200:
            shodan_data = shodan_response.json()
            telemetry["ports"] = shodan_data.get("ports", [])
            telemetry["vulns"] = shodan_data.get("vulns", [])
            telemetry["tags"] = shodan_data.get("tags", [])
            telemetry["hostnames"] = shodan_data.get("hostnames", [])

    except requests.RequestException as err:
        telemetry["error"] = f"Network error: {str(err)}"

    return telemetry


def evaluate_risk(telemetry: dict) -> dict:

    score = 0
    reasons = []

    vuln_count = len(telemetry["vulns"])
    if vuln_count > 0:
        score += 40
        reasons.append(f"Detected {vuln_count} known CVE vulnerabilities")

    suspicious_tags = {"tor", "vpn", "scanner", "honeypot", "compromised", "malware"}
    matched_tags = set(telemetry["tags"]).intersection(suspicious_tags)
    if matched_tags:
        score += 30
        reasons.append(f"Flagged with threat tags: {', '.join(matched_tags)}")

    if telemetry["is_proxy_or_hosting"]:
        score += 20
        reasons.append("Traffic originates from Hosting / Proxy / VPN infrastructure")

    port_count = len(telemetry["ports"])
    if port_count > 5:
        score += 10
        reasons.append(f"High number of exposed ports ({port_count} open)")

    final_score = min(score, 100)

    if final_score >= 60:
        verdict = "MALICIOUS / HIGH RISK"
    elif final_score >= 30:
        verdict = "SUSPICIOUS / MEDIUM RISK"
    else:
        verdict = "BENIGN / LOW RISK"
        if not reasons:
            reasons.append("No significant threat indicators found")

    telemetry["risk_score"] = final_score
    telemetry["verdict"] = verdict
    telemetry["risk_reasons"] = reasons

    return telemetry


if __name__ == "__main__":
    sample_ip = "45.33.32.156"
    print(f"[*] Running triage for IP: {sample_ip}...")

    raw_data = fetch_ip_data(sample_ip)
    final_report = evaluate_risk(raw_data)

    print(f"\n--- SOC TRIAGE SUMMARY ---")
    print(f"Target IP : {final_report['ip']}")
    print(f"ISP / Org : {final_report['isp']} ({final_report['country']})")
    print(f"Risk Score: {final_report['risk_score']}/100")
    print(f"Verdict   : {final_report['verdict']}")
    print(f"Reasons   : {final_report['risk_reasons']}")
    print(f"Open Ports: {final_report['ports']}")