from typing import List, Dict, Any
import httpx

def check_cookies(response: httpx.Response, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    
    # Extract raw Set-Cookie headers
    cookie_headers = response.headers.get_list("set-cookie")
    if not cookie_headers:
        return findings

    is_https = target_url.lower().startswith("https://")

    for raw_cookie in cookie_headers:
        cookie_parts = [p.strip() for p in raw_cookie.split(";")]
        if not cookie_parts:
            continue
            
        cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else cookie_parts[0]
        cookie_attrs_lower = [p.lower() for p in cookie_parts[1:]]

        has_secure = any(attr == "secure" for attr in cookie_attrs_lower)
        has_httponly = any(attr == "httponly" for attr in cookie_attrs_lower)
        samesite_attr = next((attr for attr in cookie_attrs_lower if attr.startswith("samesite")), None)

        # 1. Missing HttpOnly
        if not has_httponly:
            findings.append({
                "vuln_id": "SEC-CK-001",
                "title": f"Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                "severity": "MEDIUM",
                "category": "Cookies",
                "description": f"The cookie '{cookie_name}' does not specify the 'HttpOnly' flag, permitting JavaScript access via document.cookie.",
                "evidence": f"Set-Cookie: {raw_cookie[:120]}...",
                "affected_url": target_url,
                "potential_impact": "If an XSS vulnerability exists on the site, malicious scripts can steal session cookies and hijack user accounts.",
                "remediation_recommendation": f"Add the 'HttpOnly' flag when setting cookie '{cookie_name}'."
            })

        # 2. Missing Secure flag (on HTTPS)
        if is_https and not has_secure:
            findings.append({
                "vuln_id": "SEC-CK-002",
                "title": f"Cookie Missing 'Secure' Flag ({cookie_name})",
                "severity": "MEDIUM",
                "category": "Cookies",
                "description": f"The cookie '{cookie_name}' is set on an HTTPS website without the 'Secure' attribute.",
                "evidence": f"Set-Cookie: {raw_cookie[:120]}...",
                "affected_url": target_url,
                "potential_impact": "The browser may transmit this cookie in unencrypted plain-text over HTTP connections, exposing it to network eavesdroppers.",
                "remediation_recommendation": f"Ensure the 'Secure' attribute is enabled for cookie '{cookie_name}'."
            })

        # 3. Missing or Lax SameSite
        if not samesite_attr:
            findings.append({
                "vuln_id": "SEC-CK-003",
                "title": f"Cookie Missing 'SameSite' Attribute ({cookie_name})",
                "severity": "LOW",
                "category": "Cookies",
                "description": f"The cookie '{cookie_name}' does not specify a SameSite attribute (Lax, Strict, or None).",
                "evidence": f"Set-Cookie: {raw_cookie[:120]}...",
                "affected_url": target_url,
                "potential_impact": "Increases susceptibility to Cross-Site Request Forgery (CSRF) and cross-site tracking.",
                "remediation_recommendation": f"Set 'SameSite=Lax' or 'SameSite=Strict' for cookie '{cookie_name}'."
            })
        elif "samesite=none" in samesite_attr and not has_secure:
            findings.append({
                "vuln_id": "SEC-CK-004",
                "title": f"Insecure SameSite=None without Secure Flag ({cookie_name})",
                "severity": "HIGH",
                "category": "Cookies",
                "description": f"The cookie '{cookie_name}' sets SameSite=None without the Secure attribute, which is rejected by modern browsers.",
                "evidence": f"Set-Cookie: {raw_cookie[:120]}...",
                "affected_url": target_url,
                "potential_impact": "Browser cookie rejection or unencrypted cross-site cookie leakage.",
                "remediation_recommendation": "When using SameSite=None, you must also specify the Secure flag."
            })

    return findings
