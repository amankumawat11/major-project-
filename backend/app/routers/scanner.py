import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scan import ScanRequest, ScanResponse
from app.security.target_validation import validate_target_security
from app.security.rate_limiter import rate_limiter
from app.services.scanner_engine import run_security_scan
from app.services.ai_explainer import enrich_vulnerability_with_ai, generate_ai_overall_assessment

router = APIRouter(prefix="/api", tags=["Scanner"])

@router.post("/scan", response_model=ScanResponse)
def perform_scan(request_data: ScanRequest, req: Request, db: Session = Depends(get_db)):
    # 1. Rate limiting check
    client_ip = req.client.host if req.client else "127.0.0.1"
    rate_limiter.check(client_ip)

    # 2. Authorization check
    if not request_data.authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization is required. You must confirm you own or have explicit permission to assess the target."
        )

    # 3. Target Security Validation & SSRF Prevention
    try:
        val_result = validate_target_security(request_data.target)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

    norm_url = val_result["normalized_url"]
    domain = val_result["domain"]
    resolved_ip = val_result["ip"]

    # 4. Execute Scanner Engine
    scan_id = str(uuid.uuid4())
    try:
        scan_result = run_security_scan(
            target_url=norm_url,
            domain=domain,
            scan_mode=request_data.scan_mode
        )
    except Exception as e:
        # Create failed scan record
        failed_scan = Scan(
            scan_id=scan_id,
            target_url=norm_url,
            target_domain=domain,
            target_ip=resolved_ip,
            scan_mode=request_data.scan_mode,
            status="failed",
            security_score=0,
            risk_level="CRITICAL",
            total_checks=0,
            scan_duration_seconds=0.0,
            error_message=f"Scan execution error: {str(e)}"
        )
        db.add(failed_scan)
        db.commit()
        db.refresh(failed_scan)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scan failed: {str(e)}"
        )

    findings = scan_result["findings"]
    score = scan_result["security_score"]
    risk_level = scan_result["risk_level"]

    # 5. Generative AI Assessment
    overall_assessment = generate_ai_overall_assessment(findings, score, domain)

    # 6. Save Scan Record
    new_scan = Scan(
        scan_id=scan_id,
        target_url=norm_url,
        target_domain=domain,
        target_ip=resolved_ip,
        scan_mode=request_data.scan_mode,
        status="completed",
        security_score=score,
        risk_level=risk_level,
        total_checks=scan_result["total_checks"],
        scan_duration_seconds=scan_result["duration"],
        overall_ai_assessment=overall_assessment
    )
    db.add(new_scan)
    db.flush()

    # 7. AI Enrichment & Save Vulnerabilities
    saved_vulns = []
    for f in findings:
        enriched = enrich_vulnerability_with_ai(f)
        vuln_record = Vulnerability(
            vuln_id=enriched.get("vuln_id", "SEC-UNKNOWN"),
            scan_id=scan_id,
            title=enriched.get("title", "Unnamed Vulnerability"),
            severity=enriched.get("severity", "LOW"),
            category=enriched.get("category", "General"),
            description=enriched.get("description", ""),
            evidence=enriched.get("evidence"),
            affected_url=enriched.get("affected_url", norm_url),
            potential_impact=enriched.get("potential_impact"),
            remediation_recommendation=enriched.get("remediation_recommendation"),
            remediation_status="Open",
            ai_explanation=enriched.get("ai_explanation"),
            ai_why_dangerous=enriched.get("ai_why_dangerous"),
            ai_real_world_example=enriched.get("ai_real_world_example"),
            ai_remediation_steps=enriched.get("ai_remediation_steps"),
            ai_code_example=enriched.get("ai_code_example"),
            ai_code_language=enriched.get("ai_code_language", "nginx"),
            ai_developer_action=enriched.get("ai_developer_action")
        )
        db.add(vuln_record)
        saved_vulns.append(vuln_record)

    db.commit()
    db.refresh(new_scan)

    return new_scan
