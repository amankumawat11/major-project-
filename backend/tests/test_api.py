import pytest
from app.main import health_check
from app.database import SessionLocal
from app.routers.history import get_dashboard_stats, get_scans
from app.routers.vulnerabilities import get_vulnerabilities
from app.routers.assistant import chat_with_assistant
from app.schemas.chat import ChatMessageRequest
from app.schemas.scan import ScanRequest
from app.security.target_validation import validate_target_security

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_health_endpoint():
    result = health_check()
    assert result["status"] == "healthy"
    assert result["service"] == "SecureExplain AI API"

def test_dashboard_stats_endpoint(db_session):
    stats = get_dashboard_stats(db=db_session)
    assert hasattr(stats, "total_scans")
    assert hasattr(stats, "total_vulnerabilities")
    assert hasattr(stats, "avg_security_score")
    assert isinstance(stats.total_scans, int)

def test_get_scans_endpoint(db_session):
    scans = get_scans(db=db_session)
    assert isinstance(scans, list)

def test_get_vulnerabilities_endpoint(db_session):
    vulns = get_vulnerabilities(db=db_session)
    assert isinstance(vulns, list)

def test_chat_assistant_endpoint(db_session):
    req = ChatMessageRequest(
        message="What is an SSL certificate and why is it important?",
        session_id="test-session"
    )
    resp = chat_with_assistant(req, db=db_session)
    assert resp.role == "assistant"
    assert len(resp.content) > 20
    assert "SSL" in resp.content or "certificate" in resp.content.lower()

def test_target_validation_rejects_localhost():
    with pytest.raises(ValueError, match="Scanning internal or loopback hostname"):
        validate_target_security("localhost")

def test_target_validation_rejects_private_ips():
    with pytest.raises(ValueError, match="private, loopback, or reserved"):
        validate_target_security("192.168.1.1")
