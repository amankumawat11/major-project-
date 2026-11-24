import time
import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse
from app.services.ssl_checker import check_ssl_tls
from app.services.header_checker import check_headers_and_disclosure
from app.services.cookie_checker import check_cookies
from app.services.dns_checker import check_dns_and_email_security, check_authorized_ports
from app.services.sensitive_paths_checker import check_sensitive_paths
from app.security.target_validation import is_ip_blocked

def calculate_security_score(findings: List[Dict[str, Any]], target_url: str = "") -> Dict[str, Any]:
    score = 100
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    info_count = sum(1 for f in findings if f.get("severity") == "INFORMATIONAL")

    vuln_ids = {f.get("vuln_id") for f in findings}

    # 1. SSL/TLS Cryptography
    if "SEC-SSL-001" in vuln_ids:  # Plain HTTP
        score -= 40
    if "SEC-SSL-002" in vuln_ids:  # Expired SSL
        score -= 35
    if "SEC-SSL-006" in vuln_ids:  # Untrusted certificate
        score -= 30
    if "SEC-SSL-004" in vuln_ids:  # Deprecated TLS
        score -= 15
    if "SEC-SSL-003" in vuln_ids:  # Expiring soon
        score -= 8
    if "SEC-SSL-005" in vuln_ids:  # Missing SAN
        score -= 4

    # 2. Defense-in-Depth HTTP Headers
    if "SEC-HDR-001" in vuln_ids:  # Missing CSP
        score -= 12
    if "SEC-HDR-007" in vuln_ids:  # Permissive CSP
        score -= 6
    if "SEC-HDR-002" in vuln_ids:  # Missing HSTS
        score -= 10
    if "SEC-HDR-008" in vuln_ids:  # Short HSTS max-age
        score -= 3
    if "SEC-HDR-003" in vuln_ids:  # Missing nosniff
        score -= 6
    if "SEC-HDR-004" in vuln_ids:  # Missing X-Frame-Options
        score -= 6
    if "SEC-HDR-005" in vuln_ids:  # Missing Referrer-Policy
        score -= 4
    if "SEC-HDR-006" in vuln_ids:  # Missing Permissions-Policy
        score -= 2
    if "SEC-CORS-001" in vuln_ids: # Wildcard CORS *
        score -= 4

    # 3. Information Disclosure
    if "SEC-PATH-001" in vuln_ids or "SEC-PATH-002" in vuln_ids:
        score -= 35
    if "SEC-DISC-001" in vuln_ids:  # Server version disclosure
        score -= 5
    if "SEC-DISC-002" in vuln_ids:  # Tech header disclosure
        score -= 4

    # 4. Cookies
    if "SEC-CK-001" in vuln_ids:  # Missing HttpOnly
        score -= 4
    if "SEC-CK-002" in vuln_ids:  # Missing Secure
        score -= 4
    if "SEC-CK-003" in vuln_ids:  # Missing SameSite
        score -= 2
    if "SEC-CK-004" in vuln_ids:  # Insecure SameSite=None
        score -= 8

    # 5. DNS
    if "SEC-DNS-001" in vuln_ids:  # Permissive SPF (+all)
        score -= 8
    if "SEC-DNS-002" in vuln_ids:  # Missing SPF on active mail host
        score -= 5
    if "SEC-DNS-004" in vuln_ids:  # Missing DMARC on active mail host
        score -= 5
    if "SEC-DNS-003" in vuln_ids:  # DMARC p=none
        score -= 2

    # Network failure
    if "SEC-NET-001" in vuln_ids:
        score -= 25

    # Safe caps
    if "SEC-SSL-001" in vuln_ids:
        score = min(score, 25)

    score = max(0, min(100, score))

    if crit_count > 0 or score < 40:
        risk_level = "CRITICAL"
    elif high_count > 0 or score < 65:
        risk_level = "HIGH"
    elif med_count > 0 or score < 85:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "info_count": info_count
    }

def run_security_scan(target_url: str, domain: str, scan_mode: str = "quick") -> Dict[str, Any]:
    """
    Executes a comprehensive, non-intrusive security audit against the validated target.
    Modes:
      - 'quick': SSL/TLS, HTTP Security Headers, Information Disclosure, DNS/SPF/DMARC
      - 'full': Quick + Cookie Security, Common Configuration Weaknesses, Alternate Ports, Sensitive Paths
      - 'passive': SSL/TLS cert metadata, Headers, DNS records (no port or path requests)
    """
    start_time = time.time()
    findings: List[Dict[str, Any]] = []
    checks_performed = 0

    headers = {
        "User-Agent": "SecureExplain-AI-Security-Auditor/1.0 (+https://secureexplain.ai)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    # Custom redirect hook to prevent SSRF through redirect chains
    def verify_redirect(response: httpx.Response):
        if response.is_redirect:
            redirect_target = response.headers.get("location")
            if redirect_target:
                parsed_red = urlparse(redirect_target)
                if parsed_red.hostname and (parsed_red.hostname == "localhost" or parsed_red.hostname.endswith(".local")):
                    raise ValueError(f"Unsafe redirect to internal host '{parsed_red.hostname}' blocked.")

    # 1. SSL/TLS Checks
    checks_performed += 1
    ssl_findings = check_ssl_tls(target_url, domain)
    findings.extend(ssl_findings)

    # 2. HTTP Request for Headers, Cookies, and Server details
    checks_performed += 1
    client_response = None
    try:
        with httpx.Client(
            headers=headers,
            timeout=8.0,
            verify=False,
            follow_redirects=True,
            event_hooks={"response": [verify_redirect]}
        ) as client:
            client_response = client.get(target_url)

            # Header & Information Disclosure Checks
            hdr_findings = check_headers_and_disclosure(client_response, target_url)
            findings.extend(hdr_findings)

            # Cookie checks (in quick and full modes)
            if scan_mode in ("quick", "full"):
                checks_performed += 1
                ck_findings = check_cookies(client_response, target_url)
                findings.extend(ck_findings)

            # Sensitive paths probe (only in full mode)
            if scan_mode == "full":
                checks_performed += 1
                path_findings = check_sensitive_paths(target_url, client)
                findings.extend(path_findings)

    except httpx.RequestError as e:
        findings.append({
            "vuln_id": "SEC-NET-001",
            "title": "HTTP Connection Failed",
            "severity": "HIGH",
            "category": "DNS/Network",
            "description": f"Unable to establish HTTP/HTTPS connection to {target_url}: {str(e)}",
            "evidence": str(e),
            "affected_url": target_url,
            "potential_impact": "Target service is unreachable or actively dropping inbound HTTP connections.",
            "remediation_recommendation": "Verify web server operation, port forwarding, and network firewall configuration."
        })

    # 3. DNS & Email Authentication Checks
    checks_performed += 1
    dns_findings = check_dns_and_email_security(domain, target_url)
    findings.extend(dns_findings)

    # 4. Authorized alternate port probe (only in full mode)
    if scan_mode == "full":
        checks_performed += 1
        port_findings = check_authorized_ports(domain, target_url)
        findings.extend(port_findings)

    duration = round(time.time() - start_time, 2)
    score_info = calculate_security_score(findings, target_url)

    return {
        "findings": findings,
        "total_checks": checks_performed,
        "duration": duration,
        "security_score": score_info["score"],
        "risk_level": score_info["risk_level"],
        "severity_counts": score_info
    }
