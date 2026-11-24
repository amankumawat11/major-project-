import re
from typing import List, Dict, Any
import httpx

# Essential HTTP Security Headers to check
REQUIRED_SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "header_key": "content-security-policy",
        "vuln_id": "SEC-HDR-001",
        "title": "Missing Content-Security-Policy (CSP)",
        "severity": "HIGH",
        "description": "Content-Security-Policy header is missing. CSP prevents Cross-Site Scripting (XSS), data injection, and unauthorized frame embedding.",
        "impact": "Attackers can inject malicious inline scripts, hijack user sessions, or execute unauthorized actions via XSS.",
        "remediation": "Configure a Content-Security-Policy header restricting script, style, image, and frame origins (e.g. `default-src 'self'`)."
    },
    {
        "name": "Strict-Transport-Security",
        "header_key": "strict-transport-security",
        "vuln_id": "SEC-HDR-002",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "MEDIUM",
        "description": "HSTS header is missing. HSTS enforces HTTPS communication and prevents SSL stripping and downgrade attacks.",
        "impact": "Attackers performing man-in-the-middle attacks on public Wi-Fi can downgrade connections from HTTPS to HTTP.",
        "remediation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to enforce HTTPS."
    },
    {
        "name": "X-Content-Type-Options",
        "header_key": "x-content-type-options",
        "vuln_id": "SEC-HDR-003",
        "title": "Missing X-Content-Type-Options Header",
        "severity": "MEDIUM",
        "description": "The 'X-Content-Type-Options: nosniff' header is missing. It instructs browsers not to guess (sniff) MIME types.",
        "impact": "Malicious user-uploaded files (like images containing HTML/JS) can be misinterpreted and executed as executable scripts by browsers.",
        "remediation": "Add the header `X-Content-Type-Options: nosniff` to all HTTP responses."
    },
    {
        "name": "X-Frame-Options",
        "header_key": "x-frame-options",
        "vuln_id": "SEC-HDR-004",
        "title": "Missing X-Frame-Options (Clickjacking Risk)",
        "severity": "MEDIUM",
        "description": "The X-Frame-Options header (or CSP frame-ancestors directive) is missing. This leaves the site vulnerable to UI Redressing / Clickjacking.",
        "impact": "Attackers can embed the target website in an invisible iframe on a malicious site, tricking authenticated users into clicking buttons unknowingly.",
        "remediation": "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`, or configure CSP `frame-ancestors 'self'`."
    },
    {
        "name": "Referrer-Policy",
        "header_key": "referrer-policy",
        "vuln_id": "SEC-HDR-005",
        "title": "Missing or Weak Referrer-Policy",
        "severity": "LOW",
        "description": "The Referrer-Policy header is missing or configured weakly. It governs what URL information is sent in the Referer header when navigating.",
        "impact": "Sensitive query parameters, user tokens, or internal path structures may leak to external third-party servers.",
        "remediation": "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`."
    },
    {
        "name": "Permissions-Policy",
        "header_key": "permissions-policy",
        "vuln_id": "SEC-HDR-006",
        "title": "Missing Permissions-Policy Header",
        "severity": "LOW",
        "description": "Permissions-Policy (formerly Feature-Policy) allows sites to selectively restrict browser features like camera, microphone, and geolocation.",
        "impact": "Embedded third-party scripts or iframes could potentially request access to sensitive device APIs without strict site policy.",
        "remediation": "Define `Permissions-Policy: geolocation=(), microphone=(), camera=()`."
    }
]

def check_headers_and_disclosure(response: httpx.Response, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    content_type = headers_lower.get("content-type", "").lower()
    is_html = "text/html" in content_type or not content_type

    # 1. Check Missing & Present Security Headers
    for sec_hdr in REQUIRED_SECURITY_HEADERS:
        key = sec_hdr["header_key"]
        if key not in headers_lower:
            # Special check: if CSP is present and defines frame-ancestors, X-Frame-Options is redundant
            if key == "x-frame-options" and "content-security-policy" in headers_lower:
                csp_val = headers_lower["content-security-policy"].lower()
                if "frame-ancestors" in csp_val:
                    continue

            # Only flag missing HTML-specific headers if HTML content is served
            if key in ("x-frame-options", "content-security-policy") and not is_html:
                continue

            findings.append({
                "vuln_id": sec_hdr["vuln_id"],
                "title": sec_hdr["title"],
                "severity": sec_hdr["severity"],
                "category": "Headers",
                "description": sec_hdr["description"],
                "evidence": f"Header '{sec_hdr['name']}' was not returned in the server response headers.",
                "affected_url": target_url,
                "potential_impact": sec_hdr["impact"],
                "remediation_recommendation": sec_hdr["remediation"]
            })
        else:
            # Header IS present - Check strength or add POSITIVE verified finding
            val = headers_lower[key].strip()
            if key == "content-security-policy":
                if "'unsafe-inline'" in val or "'unsafe-eval'" in val:
                    findings.append({
                        "vuln_id": "SEC-HDR-007",
                        "title": "Permissive Content-Security-Policy (Unsafe Directives)",
                        "severity": "MEDIUM",
                        "category": "Headers",
                        "description": "The Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval', significantly reducing XSS protection.",
                        "evidence": f"CSP Header: {val[:120]}...",
                        "affected_url": target_url,
                        "potential_impact": "Attackers can bypass script execution boundaries using inline script tags or eval-based gadgets.",
                        "remediation_recommendation": "Migrate to cryptographic nonces or SHA-256 hashes for inline scripts and remove 'unsafe-inline' / 'unsafe-eval'."
                    })
                else:
                    findings.append({
                        "vuln_id": "SEC-HDR-000C",
                        "title": "Content-Security-Policy (CSP) Active",
                        "severity": "INFORMATIONAL",
                        "category": "Headers",
                        "description": "The website specifies an active Content-Security-Policy, mitigating Cross-Site Scripting (XSS).",
                        "evidence": f"CSP: {val[:100]}...",
                        "affected_url": target_url,
                        "potential_impact": "Status: Good. Restricts unauthorized script execution and remote domain resource loading.",
                        "remediation_recommendation": "Regularly audit allowed CSP sources and nonces."
                    })
            elif key == "strict-transport-security":
                match = re.search(r"max-age=(\d+)", val.lower())
                if match:
                    max_age = int(match.group(1))
                    if max_age < 15552000:
                        findings.append({
                            "vuln_id": "SEC-HDR-008",
                            "title": "Short HSTS max-age Duration",
                            "severity": "LOW",
                            "category": "Headers",
                            "description": f"Strict-Transport-Security max-age is set to {max_age} seconds, less than recommended 6 months.",
                            "evidence": f"HSTS Header: {val}",
                            "affected_url": target_url,
                            "potential_impact": "Browsers will forget the HTTPS enforcement requirement prematurely.",
                            "remediation_recommendation": "Increase HSTS max-age to 31536000 (1 year) and includeSubDomains."
                        })
                    else:
                        findings.append({
                            "vuln_id": "SEC-HDR-000H",
                            "title": "Strict-Transport-Security (HSTS) Active",
                            "severity": "INFORMATIONAL",
                            "category": "Headers",
                            "description": f"HSTS is actively enforcing encrypted connections across all requests (max-age: {max_age}s).",
                            "evidence": f"HSTS: {val}",
                            "affected_url": target_url,
                            "potential_impact": "Status: Good. Web browsers automatically reject unencrypted plain HTTP communication.",
                            "remediation_recommendation": "Keep HSTS enabled across all domains and subdomains."
                        })
            elif key == "x-frame-options":
                findings.append({
                    "vuln_id": "SEC-HDR-000F",
                    "title": f"Clickjacking Protection Active ({val.upper()})",
                    "severity": "INFORMATIONAL",
                    "category": "Headers",
                    "description": f"The site specifies framing restrictions with X-Frame-Options: {val}.",
                    "evidence": f"X-Frame-Options: {val}",
                    "affected_url": target_url,
                    "potential_impact": "Status: Good. Protects authenticated visitors from UI redressing attacks.",
                    "remediation_recommendation": "Maintain SAMEORIGIN or DENY framing rules."
                })
            elif key == "x-content-type-options" and "nosniff" in val.lower():
                findings.append({
                    "vuln_id": "SEC-HDR-000N",
                    "title": "MIME-Sniffing Defense Active (nosniff)",
                    "severity": "INFORMATIONAL",
                    "category": "Headers",
                    "description": "Browsers are prevented from MIME-sniffing responses away from the declared content-type.",
                    "evidence": f"X-Content-Type-Options: {val}",
                    "affected_url": target_url,
                    "potential_impact": "Status: Good. Prevents malicious user uploads from being executed as scripts.",
                    "remediation_recommendation": "Maintain X-Content-Type-Options: nosniff on all responses."
                })

    # 2. CORS Wildcard Check
    cors_header = headers_lower.get("access-control-allow-origin")
    if cors_header == "*":
        findings.append({
            "vuln_id": "SEC-CORS-001",
            "title": "Wildcard Cross-Origin Resource Sharing (CORS *)",
            "severity": "LOW",
            "category": "Headers",
            "description": "The response specifies 'Access-Control-Allow-Origin: *', permitting any third-party domain to read resources.",
            "evidence": "Access-Control-Allow-Origin: *",
            "affected_url": target_url,
            "potential_impact": "If applied on authenticated or private endpoints, external sites can read sensitive user data.",
            "remediation_recommendation": "Restrict Access-Control-Allow-Origin to specific trusted domains rather than wildcard *."
        })

    # 3. Information Disclosure via Headers
    server_header = headers_lower.get("server")
    if server_header:
        if re.search(r"\d+\.\d+", server_header):
            findings.append({
                "vuln_id": "SEC-DISC-001",
                "title": f"Detailed Server Version Disclosure ({server_header})",
                "severity": "LOW",
                "category": "Information Disclosure",
                "description": f"The 'Server' header exposes specific server software and version numbers: '{server_header}'.",
                "evidence": f"Server: {server_header}",
                "affected_url": target_url,
                "potential_impact": "Assists attackers in fingerprinting known CVEs and targeting specific unpatched software versions.",
                "remediation_recommendation": "Configure ServerTokens Prod (Apache) or server_tokens off (Nginx) to suppress version details."
            })
        else:
            findings.append({
                "vuln_id": "SEC-DISC-000",
                "title": "Server Version Banners Protected",
                "severity": "INFORMATIONAL",
                "category": "Information Disclosure",
                "description": "The web server does not disclose software patch versions, reducing automated vulnerability fingerprinting.",
                "evidence": f"Server: {server_header}",
                "affected_url": target_url,
                "potential_impact": "Status: Good. Minimizes reconnaissance surface for automated vulnerability scanners.",
                "remediation_recommendation": "Continue keeping detailed server tokens suppressed."
            })
    else:
        findings.append({
            "vuln_id": "SEC-DISC-000H",
            "title": "Server Banner Completely Hidden",
            "severity": "INFORMATIONAL",
            "category": "Information Disclosure",
            "description": "No 'Server' header is disclosed in HTTP responses.",
            "evidence": "Server header is absent.",
            "affected_url": target_url,
            "potential_impact": "Status: Good. Conceals backend server software from automated fingerprinting.",
            "remediation_recommendation": "Continue suppressing server header signatures."
        })

    # Technology disclosures (X-Powered-By, etc.)
    tech_headers = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
    for th in tech_headers:
        if th in headers_lower:
            val = headers_lower[th]
            findings.append({
                "vuln_id": "SEC-DISC-002",
                "title": f"Technology Disclosure Header ({th.upper()})",
                "severity": "LOW",
                "category": "Information Disclosure",
                "description": f"The response contains '{th}: {val}', disclosing backend framework technology.",
                "evidence": f"{th}: {val}",
                "affected_url": target_url,
                "potential_impact": "Reveals framework versions and helps adversaries craft framework-specific exploit vectors.",
                "remediation_recommendation": f"Disable the '{th}' header in your web framework (e.g., `app.disable('x-powered-by')` in Express)."
            })

    return findings
