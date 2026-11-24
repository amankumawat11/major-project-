from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.services.report_generator import generate_scan_pdf_report

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/{scan_id}")
def download_scan_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")

    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

    scan_dict = {
        "scan_id": scan.scan_id,
        "target_url": scan.target_url,
        "target_domain": scan.target_domain,
        "target_ip": scan.target_ip,
        "scan_mode": scan.scan_mode,
        "security_score": scan.security_score,
        "risk_level": scan.risk_level,
        "scan_duration_seconds": scan.scan_duration_seconds,
        "overall_ai_assessment": scan.overall_ai_assessment,
        "created_at": scan.created_at
    }

    vulns_list = [
        {
            "vuln_id": v.vuln_id,
            "title": v.title,
            "severity": v.severity,
            "category": v.category,
            "description": v.description,
            "evidence": v.evidence,
            "potential_impact": v.potential_impact,
            "remediation_recommendation": v.remediation_recommendation,
            "ai_explanation": v.ai_explanation,
            "ai_why_dangerous": v.ai_why_dangerous,
            "ai_remediation_steps": v.ai_remediation_steps,
            "ai_code_example": v.ai_code_example,
        }
        for v in vulnerabilities
    ]

    try:
        pdf_bytes = generate_scan_pdf_report(scan_dict, vulns_list)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF report: {str(e)}"
        )

    filename = f"SecureExplain_Report_{scan.target_domain}_{scan.scan_id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )
