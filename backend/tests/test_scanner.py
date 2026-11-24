import pytest
from app.services.scanner_engine import calculate_security_score
from app.services.ai_explainer import generate_ai_overall_assessment, enrich_vulnerability_with_ai

def test_calculate_security_score_perfect():
    result = calculate_security_score([])
    assert result["score"] == 100
    assert result["risk_level"] == "LOW"

def test_calculate_security_score_deductions():
    findings = [
        {"vuln_id": "SEC-SSL-002", "severity": "CRITICAL"},  # -35
        {"vuln_id": "SEC-HDR-001", "severity": "HIGH"},      # -12
        {"vuln_id": "SEC-HDR-002", "severity": "MEDIUM"},    # -10
        {"vuln_id": "SEC-HDR-005", "severity": "LOW"}        # -4
    ]
    # 100 - 35 - 12 - 10 - 4 = 39
    result = calculate_security_score(findings)
    assert result["score"] == 39
    assert result["risk_level"] == "CRITICAL"
    assert result["critical_count"] == 1
    assert result["high_count"] == 1
    assert result["medium_count"] == 1
    assert result["low_count"] == 1

def test_ai_assessment_generation():
    findings = [{"severity": "HIGH", "title": "Missing CSP"}]
    assessment = generate_ai_overall_assessment(findings, 75, "example.com")
    assert isinstance(assessment, str)
    assert len(assessment) > 20
    assert "example.com" in assessment

def test_enrich_vulnerability_with_ai_fallback():
    finding = {
        "vuln_id": "SEC-HDR-001",
        "title": "Missing Content-Security-Policy (CSP)",
        "severity": "HIGH",
        "category": "Headers",
        "description": "CSP header missing",
        "evidence": "None",
        "affected_url": "https://example.com"
    }
    enriched = enrich_vulnerability_with_ai(finding)
    assert "ai_explanation" in enriched
    assert "ai_why_dangerous" in enriched
    assert "ai_code_example" in enriched
    assert "Content-Security-Policy" in enriched["ai_code_example"]
