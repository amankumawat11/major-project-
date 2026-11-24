import socket
from typing import List, Dict, Any, Optional
import dns.resolver

def check_dns_and_email_security(domain: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []

    # Initialize resolver with short timeout
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. Check SPF (Sender Policy Framework)
    has_spf = False
    try:
        txt_records = resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt_string = "".join(b.decode("utf-8", errors="ignore") for b in rdata.strings)
            if "v=spf1" in txt_string:
                has_spf = True
                # Check for weak SPF (+all or ?all)
                if "+all" in txt_string:
                    findings.append({
                        "vuln_id": "SEC-DNS-001",
                        "title": "Permissive SPF Record (+all)",
                        "severity": "HIGH",
                        "category": "DNS/Network",
                        "description": f"The domain's SPF record contains '+all', allowing any mail server on the internet to send email on behalf of {domain}.",
                        "evidence": f"SPF TXT Record: {txt_string}",
                        "affected_url": domain,
                        "potential_impact": "Threat actors can easily forge phishing emails impersonating your domain without triggering spam filters.",
                        "remediation_recommendation": "Replace '+all' with '~all' (SoftFail) or '-all' (HardFail) in your SPF record."
                    })
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        has_spf = False

    if not has_spf:
        findings.append({
            "vuln_id": "SEC-DNS-002",
            "title": "Missing SPF Record (Email Spoofing Risk)",
            "severity": "MEDIUM",
            "category": "DNS/Network",
            "description": f"No valid SPF (v=spf1) record was found for domain {domain}.",
            "evidence": f"TXT query for {domain} yielded no SPF record.",
            "affected_url": domain,
            "potential_impact": "Attackers can spoof email addresses under your domain name, conducting phishing campaigns targeting your users and customers.",
            "remediation_recommendation": "Publish a TXT record with SPF policy (e.g. `v=spf1 include:_spf.google.com ~all`)."
        })

    # 2. Check DMARC
    dmarc_domain = f"_dmarc.{domain}"
    has_dmarc = False
    try:
        dmarc_records = resolver.resolve(dmarc_domain, "TXT")
        for rdata in dmarc_records:
            txt_string = "".join(b.decode("utf-8", errors="ignore") for b in rdata.strings)
            if "v=DMARC1" in txt_string:
                has_dmarc = True
                if "p=none" in txt_string:
                    findings.append({
                        "vuln_id": "SEC-DNS-003",
                        "title": "DMARC Policy Set to 'none' (Monitoring Only)",
                        "severity": "LOW",
                        "category": "DNS/Network",
                        "description": "The DMARC policy is set to 'p=none', which logs reports but does not block or quarantine unauthorized spoofed emails.",
                        "evidence": f"DMARC TXT: {txt_string}",
                        "affected_url": dmarc_domain,
                        "potential_impact": "Spoofed emails will still reach recipient inboxes despite failing authentication.",
                        "remediation_recommendation": "Progressively transition DMARC policy from `p=none` to `p=quarantine` and ultimately `p=reject`."
                    })
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        has_dmarc = False

    if not has_dmarc:
        findings.append({
            "vuln_id": "SEC-DNS-004",
            "title": "Missing DMARC Record",
            "severity": "MEDIUM",
            "category": "DNS/Network",
            "description": f"No DMARC policy record was detected at {dmarc_domain}.",
            "evidence": f"TXT lookup on {dmarc_domain} returned no DMARC record.",
            "affected_url": dmarc_domain,
            "potential_impact": "Receiving mail servers have no verified instruction on how to handle unauthenticated email from your domain.",
            "remediation_recommendation": f"Create a TXT record for '{dmarc_domain}' with `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}`."
        })

    return findings

def check_authorized_ports(domain: str, target_url: str) -> List[Dict[str, Any]]:
    """
    Safe, non-intrusive probe of common standard web services only (80, 443, 8080, 8443).
    Strictly rate-limited with 1.5s timeout.
    """
    findings = []
    ports_to_check = [
        (8080, "HTTP Alternate"),
        (8443, "HTTPS Alternate")
    ]

    for port, label in ports_to_check:
        try:
            with socket.create_connection((domain, port), timeout=1.5):
                findings.append({
                    "vuln_id": f"SEC-PORT-{port}",
                    "title": f"Exposed Alternate Web Port ({port} - {label})",
                    "severity": "LOW",
                    "category": "DNS/Network",
                    "description": f"Port {port} ({label}) is publicly reachable on {domain}.",
                    "evidence": f"TCP port {port} is open and accepting socket connections.",
                    "affected_url": f"http://{domain}:{port}",
                    "potential_impact": "Exposing staging, administrative, or non-production web servers on alternate ports increases attack surface.",
                    "remediation_recommendation": f"If port {port} is for internal/development purposes, restrict access using network firewall / security groups."
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    return findings
