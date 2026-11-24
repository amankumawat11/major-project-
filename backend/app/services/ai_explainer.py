import os
import json
import logging
from typing import Dict, Any, List, Optional
from app.config import settings

logger = logging.getLogger("secureexplain.ai")

# Pre-computed rich cybersecurity knowledge-base for robust fallback
FALLBACK_KNOWLEDGE_BASE = {
    "SEC-HDR-001": {
        "explanation": "Content-Security-Policy (CSP) is an HTTP header that acts like a strict security guard for your website. It specifies exactly which trusted domains and sources are allowed to run JavaScript, load images, styles, and frames on your pages.",
        "why_dangerous": "Without a CSP, if a hacker finds any place where user input is reflected into your website (Cross-Site Scripting or XSS), they can inject malicious JavaScript to steal user passwords, hijack sessions, or deface your site.",
        "real_world_example": "A malicious user posts a comment on your blog containing '<script src=\"https://evil-site.com/stealer.js\"></script>'. Without CSP, any user reading that comment will load and execute the attacker's script.",
        "remediation_steps": "1. Review all scripts and external resources currently loaded on your site.\n2. Create a Content-Security-Policy header.\n3. Start with 'default-src 'self'' and whitelist necessary CDNs.\n4. Deploy first in report-only mode (Content-Security-Policy-Report-Only) to test before strict enforcement.",
        "code_language": "nginx",
        "code_example": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://trustedscripts.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\" always;",
        "developer_action": "Add a Content-Security-Policy header in your web server (Nginx/Apache) or application middleware."
    },
    "SEC-HDR-002": {
        "explanation": "HTTP Strict Transport Security (HSTS) is a header that forces web browsers to always communicate with your website through an encrypted HTTPS connection, never unencrypted HTTP.",
        "why_dangerous": "When users type 'example.com' without 'https://', browsers initially attempt an HTTP connection before being redirected. A hacker on public Wi-Fi can intercept that initial request (SSL Stripping) and eavesdrop on all traffic.",
        "real_world_example": "A customer connects to public airport Wi-Fi. An attacker intercepts their request to your website, keeps the connection between them and the customer as unencrypted HTTP, while connecting to your server over HTTPS, intercepting all login data.",
        "remediation_steps": "1. Ensure all pages and subdomains are working flawlessly on HTTPS.\n2. Configure the Strict-Transport-Security header with a long max-age (at least 6-12 months).\n3. Include subdomains and optionally apply for HSTS preload.",
        "code_language": "nginx",
        "code_example": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        "developer_action": "Add the Strict-Transport-Security header to all HTTPS server blocks."
    },
    "SEC-HDR-003": {
        "explanation": "X-Content-Type-Options: nosniff prevents web browsers from guessing ('MIME sniffing') the content type of files received from your server.",
        "why_dangerous": "If your site allows user uploads (such as avatars or text files), an attacker could upload a text or image file containing JavaScript. Without 'nosniff', a browser might guess the file is a script and execute it.",
        "real_world_example": "A user uploads an avatar file 'profile.jpg' containing malicious JavaScript. A browser sniffs the MIME type as HTML/JavaScript instead of JPEG, executing malicious code inside the victim's session.",
        "remediation_steps": "Add 'X-Content-Type-Options: nosniff' header to all server responses.",
        "code_language": "apache",
        "code_example": "Header always set X-Content-Type-Options \"nosniff\"",
        "developer_action": "Enable the X-Content-Type-Options: nosniff response header globally."
    },
    "SEC-HDR-004": {
        "explanation": "X-Frame-Options controls whether your website can be embedded inside an <iframe> on other websites.",
        "why_dangerous": "Without this header, malicious websites can embed your site inside a transparent iframe overlaid on top of a fake game or survey. Users think they are clicking the game, but they are actually performing sensitive actions on your site (Clickjacking).",
        "real_world_example": "An attacker creates a phishing page with a transparent iframe of your site's 'Delete Account' or 'Transfer Funds' button positioned directly under a 'Click here to claim prize' button.",
        "remediation_steps": "Add X-Frame-Options set to DENY or SAMEORIGIN, or configure the 'frame-ancestors' directive in your CSP.",
        "code_language": "javascript",
        "code_example": "// Express.js (Node.js)\nconst helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));",
        "developer_action": "Set X-Frame-Options: SAMEORIGIN or DENY across all application responses."
    },
    "SEC-HDR-005": {
        "explanation": "The Referrer-Policy header controls how much URL path and query information is sent in the 'Referer' header when a user clicks a link taking them to an external website.",
        "why_dangerous": "If your internal URLs contain sensitive query parameters (like password reset tokens, user IDs, or private document links), these might leak to third-party servers.",
        "real_world_example": "A user clicks a link to an external help article from a URL like 'https://example.com/reset-password?token=secret123'. The external server logs this referer and captures the secret token.",
        "remediation_steps": "Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        "code_language": "nginx",
        "code_example": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "developer_action": "Add Referrer-Policy: strict-origin-when-cross-origin to your server headers."
    },
    "SEC-SSL-001": {
        "explanation": "The website is using plain-text unencrypted HTTP instead of HTTPS.",
        "why_dangerous": "All information transmitted between the visitor's browser and your web server travels in clear text across the internet, allowing anyone on the network path to read or tamper with the data.",
        "real_world_example": "A user logs into the site while using coffee shop Wi-Fi. An attacker using a basic network packet capture tool sees the username and password in plain text.",
        "remediation_steps": "1. Obtain a free SSL/TLS certificate from Let's Encrypt or your hosting provider.\n2. Install the certificate on your web server.\n3. Configure an automatic 301 HTTP-to-HTTPS redirect.",
        "code_language": "nginx",
        "code_example": "server {\n    listen 80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}",
        "developer_action": "Install a valid TLS certificate and configure automatic HTTP to HTTPS redirect."
    },
    "SEC-DNS-002": {
        "explanation": "Sender Policy Framework (SPF) is a DNS record that lists the mail servers authorized to send email from your domain name.",
        "why_dangerous": "Without an SPF record, scammers can send fraudulent emails that appear to originate directly from '@yourdomain.com' to trick your customers or partners into wire fraud or credential theft.",
        "real_world_example": "A criminal sends an email spoofing 'billing@yourdomain.com' to your clients asking them to send invoice payments to a new bank account. Receiving servers have no way to verify it wasn't you.",
        "remediation_steps": "Add a TXT record to your domain's DNS containing your authorized mail delivery providers.",
        "code_language": "text",
        "code_example": "v=spf1 include:_spf.google.com ~all",
        "developer_action": "Publish an SPF TXT record in your DNS provider control panel."
    },
    "SEC-PATH-001": {
        "explanation": "Your '.env' environment configuration file is publicly accessible over the web.",
        "why_dangerous": "The .env file typically contains all your most sensitive secrets: database passwords, API secret keys, Stripe tokens, and encryption keys. Exposing it means instant total compromise.",
        "real_world_example": "An automated bot scans for '/.env', downloads your file, extracts your AWS credentials, and spins up thousands of dollars of cryptocurrency mining servers within minutes.",
        "remediation_steps": "1. Immediately rotate all passwords and API keys contained in that .env file.\n2. Configure your web server to forbid access to any file beginning with a dot.\n3. Move the .env file outside of the web server document root.",
        "code_language": "nginx",
        "code_example": "location ~ /\\. {\n    deny all;\n    access_log off;\n    log_not_found off;\n}",
        "developer_action": "Immediately revoke exposed secrets and block web server access to all dotfiles."
    }
}

def generate_ai_overall_assessment(findings: List[Dict[str, Any]], score: int, domain: str) -> str:
    """
    Generates a concise 2-3 sentence overview of the website's security posture.
    """
    api_key = settings.GEMINI_API_KEY
    if api_key and api_key != "your_gemini_api_key_here":
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            vuln_summary = ", ".join([f"{f.get('title')} ({f.get('severity')})" for f in findings[:6]])
            prompt = (
                f"You are a cybersecurity expert. Provide a concise, clear 2-3 sentence executive assessment "
                f"for the website '{domain}'. The website received a security score of {score}/100. "
                f"Detected security findings: {vuln_summary if vuln_summary else 'No major issues detected.'}. "
                f"Summarize what is secure, what weaknesses need attention, and what threats they pose. "
                f"Do not use markdown headers or bullet points; output only the clean paragraph."
            )
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            logger.warning(f"Gemini API call failed for assessment, using knowledge fallback: {e}")

    # Fallback assessment based on actual findings and score
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    if crit_count > 0:
        return (
            f"The website for {domain} has critical vulnerabilities that require immediate attention. "
            f"Sensitive assets or configurations are exposed, creating significant risk of unauthorized access or data leakage. "
            f"Prioritize remediating the {crit_count} critical finding(s) as soon as possible."
        )
    elif high_count > 0:
        return (
            f"The website for {domain} has basic security in place, but several high-risk security weaknesses were detected. "
            f"These missing defenses (such as security headers or unencrypted protocols) could expose users to common web attacks "
            f"including Cross-Site Scripting (XSS) and content injection."
        )
    elif med_count > 0:
        return (
            f"The website for {domain} demonstrates standard security controls, but displays moderate weaknesses in security headers "
            f"or email authentication records. Applying the recommended defense-in-depth headers will substantially enhance your resistance to automated attacks."
        )
    else:
        return (
            f"The website for {domain} has achieved a solid security posture with essential HTTPS, strict security headers, and domain configurations verified. "
            f"Continue periodic security scans and keep server components regularly updated."
        )

def enrich_vulnerability_with_ai(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches a vulnerability with beginner-friendly AI explanations, real-world examples,
    and remediation code.
    """
    vuln_id = vuln.get("vuln_id", "")
    title = vuln.get("title", "")
    severity = vuln.get("severity", "LOW")
    category = vuln.get("category", "")
    description = vuln.get("description", "")
    evidence = vuln.get("evidence", "")

    api_key = settings.GEMINI_API_KEY
    if api_key and api_key != "your_gemini_api_key_here":
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            prompt = f"""
You are an expert cybersecurity educator. Convert this technical vulnerability finding into a beginner-friendly explanation.
FINDING DETAILS:
- Vulnerability: {title}
- Severity: {severity}
- Category: {category}
- Technical Evidence: {evidence}
- Description: {description}

Provide your response strictly in the following JSON structure:
{{
  "explanation": "Simple explanation of what this means for a non-technical website owner (2-3 sentences)",
  "why_dangerous": "Clear explanation of the danger and potential consequences",
  "real_world_example": "A simple hypothetical scenario of how an attacker abuses this weakness",
  "remediation_steps": "Step-by-step practical instructions to fix it",
  "code_language": "nginx, apache, or javascript",
  "code_example": "Concrete configuration or code snippet to resolve this",
  "developer_action": "One concise action item for the developer"
}}
"""
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            if response and response.text:
                # Clean any markdown code fences if present
                raw_json = response.text.strip()
                if raw_json.startswith("```json"):
                    raw_json = raw_json[7:]
                if raw_json.startswith("```"):
                    raw_json = raw_json[3:]
                if raw_json.endswith("```"):
                    raw_json = raw_json[:-3]
                
                data = json.loads(raw_json.strip())
                vuln["ai_explanation"] = data.get("explanation")
                vuln["ai_why_dangerous"] = data.get("why_dangerous")
                vuln["ai_real_world_example"] = data.get("real_world_example")
                vuln["ai_remediation_steps"] = data.get("remediation_steps")
                vuln["ai_code_language"] = data.get("code_language", "nginx")
                vuln["ai_code_example"] = data.get("code_example")
                vuln["ai_developer_action"] = data.get("developer_action")
                return vuln
        except Exception as e:
            logger.warning(f"Gemini API enrichment failed, falling back to knowledge base: {e}")

    # Fallback to rich pre-computed security knowledge base
    fallback = FALLBACK_KNOWLEDGE_BASE.get(vuln_id)
    if fallback:
        vuln["ai_explanation"] = fallback["explanation"]
        vuln["ai_why_dangerous"] = fallback["why_dangerous"]
        vuln["ai_real_world_example"] = fallback["real_world_example"]
        vuln["ai_remediation_steps"] = fallback["remediation_steps"]
        vuln["ai_code_language"] = fallback["code_language"]
        vuln["ai_code_example"] = fallback["code_example"]
        vuln["ai_developer_action"] = fallback["developer_action"]
    else:
        # Check if positive verified control
        if severity == "INFORMATIONAL":
            vuln["ai_explanation"] = f"{title}: This defensive control is actively implemented and verified on the website."
            vuln["ai_why_dangerous"] = "Positive defense active: Mitigates associated attack vectors and protects user sessions."
            vuln["ai_real_world_example"] = "Automated scanners and threat actors targeting this vector will find this defensive control active."
            vuln["ai_remediation_steps"] = vuln.get("remediation_recommendation") or "Verified active security control. Maintain current configuration."
            vuln["ai_code_language"] = "nginx"
            vuln["ai_code_example"] = "# Active configuration verified."
            vuln["ai_developer_action"] = "Maintain current security hygiene."
        else:
            # Default structured explanation based on category
            vuln["ai_explanation"] = f"{title} indicates that the website is missing standard security configurations in the {category} category."
            vuln["ai_why_dangerous"] = vuln.get("potential_impact") or "Without this defense, malicious actors can exploit the gap to intercept data or probe for further misconfigurations."
            vuln["ai_real_world_example"] = f"An attacker discovers this {severity.lower()}-severity issue during reconnaissance and uses it to facilitate subsequent attacks against site users."
            vuln["ai_remediation_steps"] = vuln.get("remediation_recommendation") or "Review web server documentation and configure appropriate protective directives."
            vuln["ai_code_language"] = "nginx"
            vuln["ai_code_example"] = "# Consult server documentation to apply recommended configuration."
            vuln["ai_developer_action"] = vuln.get("remediation_recommendation") or f"Implement remediation for {title}."

    return vuln

def ask_security_assistant(message: str, session_id: str, scan_context: Optional[str] = None) -> str:
    """
    Answers user cybersecurity questions or explains scan results.
    """
    api_key = settings.GEMINI_API_KEY
    if api_key and api_key != "your_gemini_api_key_here":
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            system_instruction = (
                "You are SecureExplain AI's Cybersecurity Assistant. Your mission is to explain cybersecurity concepts, "
                "vulnerabilities, headers, SSL/TLS, and website defense in friendly, practical, beginner-accessible language. "
                "Help website owners and developers secure their applications. Always advocate defensive security practices. "
                "Strictly decline to assist with unauthorized penetration testing, hacking, or exploit weaponization."
            )
            full_prompt = f"System: {system_instruction}\n"
            if scan_context:
                full_prompt += f"Recent Scan Findings Context:\n{scan_context}\n\n"
            full_prompt += f"User: {message}\nAssistant:"

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=full_prompt
            )
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            logger.warning(f"Gemini API chat failed, falling back to local assistant: {e}")

    # Intelligent local fallback chatbot for common cybersecurity queries
    msg_lower = message.lower()
    if "ssl" in msg_lower or "tls" in msg_lower or "certificate" in msg_lower:
        return (
            "**What is an SSL/TLS Certificate?**\n\n"
            "An SSL (Secure Sockets Layer) or TLS (Transport Layer Security) certificate is a digital passport for your website. "
            "It does two essential things:\n"
            "1. **Encrypts Data**: Ensures all information sent between your visitors and your server (passwords, credit cards, forms) cannot be read by eavesdroppers on the network.\n"
            "2. **Verifies Identity**: Proves to web browsers that your domain truly belongs to you and isn't an imposter.\n\n"
            "**How to get one:** You can obtain free, automatically renewing certificates using [Let's Encrypt](https://letsencrypt.org) with Certbot (`certbot --nginx` or `certbot --apache`)."
        )
    elif "csp" in msg_lower or "content-security-policy" in msg_lower or "content security policy" in msg_lower:
        return (
            "**Content-Security-Policy (CSP) Explained:**\n\n"
            "CSP is one of the most effective defenses against **Cross-Site Scripting (XSS)**. "
            "It is an HTTP header sent by your server that tells the visitor's browser: *'Only execute JavaScript files that come from these specific trusted domains, and ignore any inline scripts injected by attackers.'*\n\n"
            "**Quick Start Nginx Config:**\n"
            "```nginx\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://trusted-cdn.com;\" always;\n"
            "```\n"
            "We recommend starting in Report-Only mode (`Content-Security-Policy-Report-Only`) so you can test without breaking existing site features!"
        )
    elif "xss" in msg_lower or "cross-site scripting" in msg_lower:
        return (
            "**What is Cross-Site Scripting (XSS)?**\n\n"
            "XSS occurs when an application accepts user input (like a search query or a comment) and outputs it directly into the web page without proper escaping or sanitization. "
            "An attacker can submit malicious JavaScript code (`<script>...</script>`). When another visitor views that page, their browser executes the attacker's script!\n\n"
            "**Dangers:** Attackers can steal session cookies, impersonate the user, or redirect them to phishing sites.\n\n"
            "**Defenses:**\n"
            "1. Context-aware HTML entity encoding on all user output.\n"
            "2. Modern frameworks (React, Vue, Angular) which automatically escape variables.\n"
            "3. Enforcing a strong **Content-Security-Policy (CSP)**."
        )
    elif "sql" in msg_lower or "sqli" in msg_lower:
        return (
            "**What is SQL Injection (SQLi)?**\n\n"
            "SQL Injection occurs when user input is concatenated directly into a database query string. "
            "An attacker can input special SQL characters (like `' OR '1'='1`) to alter the query logic and bypass authentication or dump the entire database.\n\n"
            "**Remediation:** Always use **Parameterized Queries (Prepared Statements)** or an ORM like SQLAlchemy, Prisma, or Hibernate. Never format raw strings into SQL queries!"
        )
    elif "header" in msg_lower:
        return (
            "**Essential Security Headers for Every Website:**\n\n"
            "1. **Strict-Transport-Security (HSTS)**: Forces browsers to use HTTPS.\n"
            "2. **Content-Security-Policy (CSP)**: Stops Cross-Site Scripting (XSS).\n"
            "3. **X-Content-Type-Options: nosniff**: Prevents MIME-confusion attacks.\n"
            "4. **X-Frame-Options: SAMEORIGIN**: Prevents Clickjacking attacks.\n"
            "5. **Referrer-Policy: strict-origin-when-cross-origin**: Protects private URL paths from leaking.\n\n"
            "Would you like a copy-paste snippet for Nginx, Apache, or Node.js Express?"
        )
    elif "scan" in msg_lower or "result" in msg_lower:
        if scan_context:
            return f"Based on your recent scan:\n\n{scan_context}\n\nTo improve your score, focus first on resolving the high and medium risk findings shown above!"
        else:
            return "You can run a scan from the **Network Scanner** tab! Once completed, you can ask me to explain any finding or generate remediation code for your server."
    else:
        return (
            f"Hello! I am your SecureExplain AI Cybersecurity Assistant.\n\n"
            f"You asked: *\"{message}\"*\n\n"
            f"I can help you understand web security vulnerabilities, explain how to configure HTTP headers (CSP, HSTS), "
            f"secure your SSL/TLS certificates, protect cookies, or analyze findings from your website scans.\n\n"
            f"Feel free to ask questions like:\n"
            f"- *'How do I set up Content Security Policy in Nginx?'*\n"
            f"- *'Why is my certificate considered weak?'*\n"
            f"- *'What does Clickjacking mean and how does X-Frame-Options stop it?'*"
        )
