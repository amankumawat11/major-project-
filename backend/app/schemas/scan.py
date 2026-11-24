from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.schemas.vulnerability import VulnerabilityResponse

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target website URL, domain name, or authorized public IP", min_length=3, max_length=2048)
    scan_mode: str = Field(default="quick", description="quick, full, passive")
    authorized: bool = Field(default=True, description="Confirmation that the user owns or is authorized to assess this target")

class ScanResponse(BaseModel):
    id: int
    scan_id: str
    target_url: str
    target_domain: str
    target_ip: Optional[str] = None
    scan_mode: str
    status: str
    security_score: int
    risk_level: str
    total_checks: int
    scan_duration_seconds: float
    overall_ai_assessment: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    vulnerabilities: List[VulnerabilityResponse] = []

    model_config = ConfigDict(from_attributes=True)

class ScanSummary(BaseModel):
    id: int
    scan_id: str
    target_url: str
    target_domain: str
    target_ip: Optional[str] = None
    scan_mode: str
    status: str
    security_score: int
    risk_level: str
    total_checks: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    critical_risks: int
    high_risks: int
    medium_risks: int
    low_risks: int
    avg_security_score: float
    recent_scans: List[ScanSummary] = []
    severity_distribution: Dict[str, int] = {}
    category_distribution: Dict[str, int] = {}

class ScanCompareRequest(BaseModel):
    scan_id_1: str
    scan_id_2: str

class ScanCompareResponse(BaseModel):
    scan_1: ScanResponse
    scan_2: ScanResponse
    score_difference: int
    new_vulnerabilities: List[VulnerabilityResponse] = []
    resolved_vulnerabilities: List[VulnerabilityResponse] = []
    common_vulnerabilities: List[VulnerabilityResponse] = []
