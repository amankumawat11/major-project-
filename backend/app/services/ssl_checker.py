import socket
import ssl
import certifi
from datetime import datetime, timezone
from typing import List, Dict, Any
from urllib.parse import urlparse

def check_ssl_tls(target_url: str, domain: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(target_url)

    # Check if target is served over HTTP only
    if parsed.scheme == "http":
        findings.append({
            "vuln_id": "SEC-SSL-001",
            "title": "Unencrypted HTTP Protocol in Use",
            "severity": "HIGH",
            "category": "SSL/TLS",
            "description": "The target website is accessed over unencrypted plain-text HTTP. Data exchanged between the user and the server can be intercepted or manipulated.",
            "evidence": f"URL Scheme: {parsed.scheme}:// for host {domain}",
            "affected_url": target_url,
            "potential_impact": "Man-in-the-Middle (MitM) attackers can eavesdrop on sensitive credentials, session tokens, and inject malicious scripts.",
            "remediation_recommendation": "Enforce HTTPS by obtaining a valid TLS certificate and configuring HTTP-to-HTTPS 301 redirection."
        })
        return findings

    port = parsed.port or 443

    # Attempt TLS connection and certificate inspection using standard CA store
    try:
        context = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((domain, port), timeout=6.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                # 1. Certificate Expiry Check
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Format: 'May  5 12:00:00 2026 GMT'
                    expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_remaining = (expires_dt - now_dt).days

                    if days_remaining < 0:
                        findings.append({
                            "vuln_id": "SEC-SSL-002",
                            "title": "Expired SSL/TLS Certificate",
                            "severity": "CRITICAL",
                            "category": "SSL/TLS",
                            "description": f"The SSL/TLS certificate expired {abs(days_remaining)} days ago on {not_after_str}.",
                            "evidence": f"Certificate notAfter: {not_after_str}, Days remaining: {days_remaining}",
                            "affected_url": target_url,
                            "potential_impact": "Browsers display prominent security warnings, preventing users from accessing the site and destroying trust.",
                            "remediation_recommendation": "Immediately renew the SSL/TLS certificate via Let's Encrypt or your Certificate Authority."
                        })
                    elif days_remaining < 15:
                        findings.append({
                            "vuln_id": "SEC-SSL-003",
                            "title": "SSL/TLS Certificate Expiring Soon",
                            "severity": "MEDIUM",
                            "category": "SSL/TLS",
                            "description": f"The certificate will expire in {days_remaining} days ({not_after_str}).",
                            "evidence": f"Expiration: {not_after_str} ({days_remaining} days left)",
                            "affected_url": target_url,
                            "potential_impact": "Service disruption when the certificate expires, resulting in browser blocking.",
                            "remediation_recommendation": "Renew the certificate before expiration and verify automatic renewal hooks (e.g. certbot renew)."
                        })

                # 2. TLS Protocol Version check
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({
                        "vuln_id": "SEC-SSL-004",
                        "title": f"Depreciated TLS Version ({tls_version})",
                        "severity": "HIGH",
                        "category": "SSL/TLS",
                        "description": f"The server negotiated connection using {tls_version}, which is deprecated and contains cryptographic flaws.",
                        "evidence": f"Negotiated Protocol: {tls_version}, Cipher: {cipher[0] if cipher else 'Unknown'}",
                        "affected_url": target_url,
                        "potential_impact": "Susceptible to protocol downgrade attacks, POODLE, BEAST, or eavesdropping.",
                        "remediation_recommendation": "Disable TLS 1.0 and TLS 1.1 on your web server and enable TLS 1.2 and TLS 1.3 only."
                    })
                
                # Check Subject Alternative Names (SAN)
                sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
                if not sans:
                    findings.append({
                        "vuln_id": "SEC-SSL-005",
                        "title": "Certificate Lacks Subject Alternative Names (SAN)",
                        "severity": "LOW",
                        "category": "SSL/TLS",
                        "description": "Modern browsers require valid SAN entries matching the target domain rather than relying solely on the Common Name.",
                        "evidence": "subjectAltName extension is absent from certificate.",
                        "affected_url": target_url,
                        "potential_impact": "Potential certificate validation warnings on strict user agents.",
                        "remediation_recommendation": "Issue a certificate that contains proper SAN extensions for your domain."
                    })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "vuln_id": "SEC-SSL-006",
            "title": "SSL/TLS Certificate Verification Failed",
            "severity": "CRITICAL",
            "category": "SSL/TLS",
            "description": f"The certificate could not be verified by standard trust stores: {e.verify_message}",
            "evidence": f"Verification error: {str(e)}",
            "affected_url": target_url,
            "potential_impact": "Users will be blocked with a severe browser security warning. Potential self-signed or improperly chained certificate.",
            "remediation_recommendation": "Install an authenticated certificate from a recognized Certificate Authority (CA) and ensure full intermediate CA chain is installed."
        })
    except ssl.SSLError as e:
        findings.append({
            "vuln_id": "SEC-SSL-007",
            "title": "TLS Handshake Error",
            "severity": "HIGH",
            "category": "SSL/TLS",
            "description": f"Failed to negotiate secure TLS handshake with the target: {str(e)}",
            "evidence": f"SSL error: {str(e)}",
            "affected_url": target_url,
            "potential_impact": "Incompatible cryptographic ciphers or broken web server SSL configuration.",
            "remediation_recommendation": "Inspect web server SSL configuration and ensure standard cipher suites and protocol versions are enabled."
        })
    except (socket.timeout, socket.error) as e:
        findings.append({
            "vuln_id": "SEC-SSL-008",
            "title": "HTTPS Port Connection Timed Out",
            "severity": "MEDIUM",
            "category": "SSL/TLS",
            "description": f"Unable to establish socket connection on port {port}: {str(e)}",
            "evidence": f"Socket error: {str(e)}",
            "affected_url": target_url,
            "potential_impact": "Target web server is either offline, blocking inbound port 443, or experiencing network timeout.",
            "remediation_recommendation": "Verify firewall rules and ensure port 443 is open and responding."
        })

    return findings
