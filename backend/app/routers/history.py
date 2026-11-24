from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from app.database import get_db
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scan import (
    ScanResponse, ScanSummary, DashboardStats,
    ScanCompareRequest, ScanCompareResponse
)
from app.schemas.vulnerability import VulnerabilityResponse

router = APIRouter(prefix="/api", tags=["History & Dashboard"])

@router.get("/scans", response_model=List[ScanSummary])
def get_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    summaries = []
    for s in scans:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == s.scan_id).all()
        summaries.append(ScanSummary(
            id=s.id,
            scan_id=s.scan_id,
            target_url=s.target_url,
            target_domain=s.target_domain,
            target_ip=s.target_ip,
            scan_mode=s.scan_mode,
            status=s.status,
            security_score=s.security_score,
            risk_level=s.risk_level,
            total_checks=s.total_checks,
            total_vulnerabilities=len(vulns),
            critical_count=sum(1 for v in vulns if v.severity == "CRITICAL"),
            high_count=sum(1 for v in vulns if v.severity == "HIGH"),
            medium_count=sum(1 for v in vulns if v.severity == "MEDIUM"),
            low_count=sum(1 for v in vulns if v.severity == "LOW"),
            created_at=s.created_at
        ))
    return summaries

@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan_detail(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    return scan

@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully.", "scan_id": scan_id}

@router.post("/scans/compare", response_model=ScanCompareResponse)
def compare_scans(req: ScanCompareRequest, db: Session = Depends(get_db)):
    scan1 = db.query(Scan).filter(Scan.scan_id == req.scan_id_1).first()
    scan2 = db.query(Scan).filter(Scan.scan_id == req.scan_id_2).first()
    if not scan1 or not scan2:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scans not found.")

    v1_titles = {v.title: v for v in scan1.vulnerabilities}
    v2_titles = {v.title: v for v in scan2.vulnerabilities}

    # scan2 is compared against scan1 (e.g. newer scan vs older scan)
    new_vulns = [v for title, v in v2_titles.items() if title not in v1_titles]
    resolved_vulns = [v for title, v in v1_titles.items() if title not in v2_titles]
    common_vulns = [v for title, v in v2_titles.items() if title in v1_titles]

    return ScanCompareResponse(
        scan_1=scan1,
        scan_2=scan2,
        score_difference=scan2.security_score - scan1.security_score,
        new_vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in new_vulns],
        resolved_vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in resolved_vulns],
        common_vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in common_vulns]
    )

@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0
    
    crit_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "CRITICAL").scalar() or 0
    high_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "HIGH").scalar() or 0
    med_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "MEDIUM").scalar() or 0
    low_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "LOW").scalar() or 0

    avg_score = db.query(func.avg(Scan.security_score)).scalar() or 100.0

    # Severity distribution
    sev_dist = {
        "CRITICAL": crit_count,
        "HIGH": high_count,
        "MEDIUM": med_count,
        "LOW": low_count
    }

    # Category distribution
    categories = db.query(Vulnerability.category, func.count(Vulnerability.id)).group_by(Vulnerability.category).all()
    cat_dist = {cat: count for cat, count in categories}

    # Recent 5 scans
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
    recent = []
    for s in scans:
        vulns = s.vulnerabilities
        recent.append(ScanSummary(
            id=s.id,
            scan_id=s.scan_id,
            target_url=s.target_url,
            target_domain=s.target_domain,
            target_ip=s.target_ip,
            scan_mode=s.scan_mode,
            status=s.status,
            security_score=s.security_score,
            risk_level=s.risk_level,
            total_checks=s.total_checks,
            total_vulnerabilities=len(vulns),
            critical_count=sum(1 for v in vulns if v.severity == "CRITICAL"),
            high_count=sum(1 for v in vulns if v.severity == "HIGH"),
            medium_count=sum(1 for v in vulns if v.severity == "MEDIUM"),
            low_count=sum(1 for v in vulns if v.severity == "LOW"),
            created_at=s.created_at
        ))

    return DashboardStats(
        total_scans=total_scans,
        total_vulnerabilities=total_vulns,
        critical_risks=crit_count,
        high_risks=high_count,
        medium_risks=med_count,
        low_risks=low_count,
        avg_security_score=round(float(avg_score), 1),
        recent_scans=recent,
        severity_distribution=sev_dist,
        category_distribution=cat_dist
    )
