from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityStatusUpdate

router = APIRouter(prefix="/api", tags=["Vulnerabilities"])

@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
def get_vulnerabilities(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)

    if severity and isinstance(severity, str) and severity.upper() != "ALL":
        query = query.filter(Vulnerability.severity == severity.upper())

    if category and isinstance(category, str) and category.upper() != "ALL":
        query = query.filter(Vulnerability.category == category)

    if status and isinstance(status, str) and status.upper() != "ALL":
        query = query.filter(Vulnerability.remediation_status == status)

    if search and isinstance(search, str):
        search_filter = f"%{search}%"
        query = query.filter(
            (Vulnerability.title.ilike(search_filter)) |
            (Vulnerability.description.ilike(search_filter)) |
            (Vulnerability.affected_url.ilike(search_filter))
        )

    return query.order_by(Vulnerability.created_at.desc()).all()

@router.patch("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability_status(vuln_id: int, update_data: VulnerabilityStatusUpdate, db: Session = Depends(get_db)):
    allowed_statuses = ["Open", "In Progress", "Fixed", "Accepted Risk"]
    if update_data.remediation_status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{update_data.remediation_status}'. Allowed values: {', '.join(allowed_statuses)}"
        )

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found.")

    vuln.remediation_status = update_data.remediation_status
    db.commit()
    db.refresh(vuln)
    return vuln
