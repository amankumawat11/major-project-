from typing import List, Dict, Any
import httpx
from urllib.parse import urljoin

# Safe, minimal list of sensitive files / configuration paths to probe non-intrusively
SAFE_PROBE_PATHS = [
    {
        "path": "/.env",
        "vuln_id": "SEC-PATH-001",
        "title": "Publicly Accessible Environment File (.env)",
        "severity": "CRITICAL",
        "signature": ["DB_", "API_KEY", "SECRET", "PASSWORD", "DATABASE_URL"],
        "description": "The web server exposes the '.env' configuration file publicly.",
        "impact": "Attackers can read backend database passwords, API credentials, and secret encryption keys, leading to complete infrastructure compromise.",
        "remediation": "Block access to all dotfiles in web server configuration (e.g., `location ~ /\\. { deny all; }` in Nginx) and store environment variables outside the webroot."
    },
    {
        "path": "/.git/HEAD",
        "vuln_id": "SEC-PATH-002",
        "title": "Exposed Git Repository Metadata (.git/HEAD)",
        "severity": "CRITICAL",
        "signature": ["ref: refs/heads/", "ref: refs/tags/"],
        "description": "The '.git' directory is publicly accessible on the web server.",
        "impact": "Adversaries can download the entire source code repository, revision history, and embedded developer credentials.",
        "remediation": "Deny web access to `/.git` directories immediately and remove the `.git` folder from the deployment document root."
    },
    {
        "path": "/robots.txt",
        "vuln_id": "SEC-PATH-003",
        "title": "Robots.txt Discloses Sensitive Administration Paths",
        "severity": "LOW",
        "signature": ["Disallow: /admin", "Disallow: /backup", "Disallow: /staging", "Disallow: /manage", "Disallow: /private"],
        "description": "The robots.txt file contains Disallow directives pointing to sensitive administrative or backup directories.",
        "impact": "While intended for search engine crawlers, robots.txt is public and gives attackers a roadmap of high-value internal paths.",
        "remediation": "Ensure administrative endpoints are secured with strong authentication and do not rely on robots.txt for obscurity."
    }
]

def check_sensitive_paths(target_url: str, client: httpx.Client) -> List[Dict[str, Any]]:
    findings = []

    for item in SAFE_PROBE_PATHS:
        probe_url = urljoin(target_url, item["path"])
        try:
            resp = client.get(probe_url, timeout=3.0, follow_redirects=False)
            if resp.status_code == 200:
                body_text = resp.text[:1000]
                matched = any(sig.lower() in body_text.lower() for sig in item["signature"])
                if matched:
                    findings.append({
                        "vuln_id": item["vuln_id"],
                        "title": item["title"],
                        "severity": item["severity"],
                        "category": "Configuration",
                        "description": item["description"],
                        "evidence": f"GET {probe_url} returned HTTP 200 with matching signature content.",
                        "affected_url": probe_url,
                        "potential_impact": item["impact"],
                        "remediation_recommendation": item["remediation"]
                    })
        except Exception:
            pass

    return findings
