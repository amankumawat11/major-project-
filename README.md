# SecureExplain AI 🛡️✨

> **Understand vulnerabilities. Fix security risks. Build safer websites.**

SecureExplain AI is an enterprise-grade full-stack cybersecurity posture auditing and Generative AI explanation platform. It conducts non-intrusive, safe security assessments against authorized websites, analyzes cryptographic configurations, evaluates HTTP response security headers, detects cookie misconfigurations, verifies DNS records (SPF/DMARC), and uses Google Gemini to translate complex vulnerabilities into beginner-friendly explanations with copy-paste remediation configuration snippets.

---

## 🌟 Key Features

1. **Defensive Website Security Scanner**
   - **Target Safety & SSRF Protections:** Strict blocking of RFC 1918 private ranges, loopback (`127.0.0.1`), link-local metadata addresses (`169.254.169.254`), and DNS rebinding protections.
   - **Three Scanning Modes:**
     - `Quick Scan`: SSL/TLS inspection, HTTP Security Headers, Information Disclosure, DNS/SPF/DMARC.
     - `Full Scan`: Quick Scan + Cookie security attributes, sensitive path exposures (`.env`, `.git/HEAD`, `robots.txt`), alternate port discovery.
     - `Passive Audit`: Publicly observable DNS, header, and SSL metadata without active path probing.

2. **Vulnerability Detection Engine**
   - **SSL/TLS Cryptography:** Certificate validity, expiry warnings, SAN extensions, and weak TLS protocol checks (`TLSv1.0`, `TLSv1.1`).
   - **HTTP Security Headers:** Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options (Clickjacking), Referrer-Policy, and Permissions-Policy.
   - **Information Disclosure:** Web server version banners (`Server: Apache/2.4.41`) and framework signatures (`X-Powered-By: Express`).
   - **Cookie Security:** `HttpOnly`, `Secure`, and `SameSite` attribute enforcement.
   - **DNS & Email Integrity:** Missing SPF records (+all spoofing risks) and DMARC enforcement.

3. **Google Gemini Generative AI Explainer**
   - **Beginner-Friendly Synthesis:** Automatically explains *What does this mean?*, *Why is it dangerous?*, *Real-World Attack Scenario*, and *Developer Action*.
   - **Actionable Remediation Code:** Concrete configuration snippets for **Nginx**, **Apache**, **Node.js (Express/Helmet)**, and **HTML/JS**.
   - **AI Overall Assessment:** Executive summary paragraph reflecting overall posture.
   - **Zero-Downtime Fallback:** Built-in high-quality cybersecurity knowledge base ensures instant, comprehensive explanations even without an API key or when offline.

4. **AI Cybersecurity Assistant Chatbot**
   - Interactive conversational assistant answering technical security questions.
   - Incorporates scan findings context into conversations.
   - Guardrailed exclusively for defensive remediation advice.

5. **Scan History & Comparative Analysis**
   - Persistent SQLite database tracking historical scans and score progression.
   - Side-by-side **Comparative Analysis Modal** revealing resolved vs. newly introduced vulnerabilities.

6. **Executive PDF Audit Reports**
   - Generates downloadable, publication-grade cybersecurity reports via ReportLab.
   - Includes score gauges, risk breakdowns, technical evidence, and a remediation checklist.

---

## 🏗️ Architecture & Technology Stack

```
secureexplain-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application & CORS setup
│   │   ├── config.py                   # Pydantic v2 settings & environment variables
│   │   ├── database.py                 # SQLAlchemy engine & session dependency
│   │   ├── models/                     # Scan, Vulnerability, and Chat models
│   │   ├── schemas/                    # Pydantic request/response schemas
│   │   ├── security/                   # SSRF guard, target validation, rate limiter
│   │   ├── services/                   # SSL, Headers, Cookies, DNS, AI & PDF engines
│   │   └── routers/                    # Scanner, History, Vulns, Assistant, Reports
│   ├── tests/                          # 17 automated unit and integration tests
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/                 # ScoreGauge, RiskBadge, VulnerabilityCard, Sidebar, Navbar
│   │   ├── pages/                      # Dashboard, Scanner, ScanHistory, Vulnerabilities, AIAssistant, Settings
│   │   ├── services/api.js             # Axios API service
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── vercel.json
├── render.yaml                         # Render deployment blueprint
├── package.json                        # Root helper commands
└── README.md
```

---

## 🚀 Quickstart & Local Setup

### Prerequisites
- **Python 3.10+** (tested on Python 3.11, 3.12, 3.14)
- **Node.js 18+** & npm

### 1. Clone & Setup Backend
```bash
# Navigate to backend directory
cd backend

# Copy environment template
cp .env.example .env

# Install Python requirements
pip install -r requirements.txt

# (Optional) Add your Google Gemini API Key in .env:
# GEMINI_API_KEY=your_actual_gemini_api_key_here

# Run backend development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Backend API interactive Swagger documentation will be available at: `http://localhost:8000/docs`

### 2. Setup Frontend
```bash
# In a new terminal, navigate to frontend
cd frontend

# Copy environment template
cp .env.example .env

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```
Frontend application will be accessible at: `http://localhost:5173`

---

## 🧪 Running Automated Tests

Run the complete backend test suite:
```bash
# Run pytest from project root
npm run test:backend

# Or directly using Python:
$env:PYTHONPATH="backend"; python -m pytest backend/tests -v
```

All 17 automated tests cover:
- Private and loopback IP blocking (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`)
- Target normalization and dangerous protocol rejection (`file://`, `gopher://`)
- Security score deduction algorithms and risk classifications
- AI overall assessment generator and rich knowledge fallback
- API route handlers and schemas (`/api/health`, `/api/dashboard/stats`, `/api/scans`, `/api/vulnerabilities`, `/api/ai/chat`)
- PDF report generation integrity

---

## ☁️ Deployment Guide

### Deploy Backend to Render
1. Push your repository to GitHub.
2. In the Render Dashboard, click **New +** > **Blueprint** and connect your repository (Render will automatically detect `render.yaml`).
3. Alternatively, create a **Web Service**:
   - **Environment:** Python
   - **Build Command:** `pip install -r backend/requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT --app-dir backend`
4. In **Environment Variables**, configure:
   - `GEMINI_API_KEY`: Your Gemini API key from Google AI Studio
   - `FRONTEND_URL`: URL of your deployed frontend (e.g., `https://secureexplain-ai.vercel.app`)
   - `DATABASE_URL`: `sqlite:///./secureexplain.db` (or PostgreSQL connection string)

### Deploy Frontend to Vercel
1. Import your GitHub repository into Vercel.
2. Set the **Root Directory** to `frontend`.
3. In **Environment Variables**, add:
   - `VITE_API_URL`: Your Render backend API URL + `/api` (e.g., `https://secureexplain-ai.onrender.com/api`)
4. Click **Deploy**. Vercel will build the Vite project using the included `vercel.json` SPA configuration.

---

## 🛡️ Responsible Security & Legal Notice

SecureExplain AI is designed solely for defensive security posture evaluation and educational assistance. Users are required to confirm ownership or explicit authorization prior to conducting scans. The scanner does not exploit vulnerabilities, inject payloads, conduct brute-force attacks, or bypass network barriers.
