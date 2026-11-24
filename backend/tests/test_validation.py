import pytest
from app.security.target_validation import (
    is_ip_blocked,
    normalize_target,
    validate_target_security
)

def test_blocked_private_and_loopback_ips():
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("192.168.1.1") is True
    assert is_ip_blocked("172.16.0.1") is True
    assert is_ip_blocked("169.254.169.254") is True
    assert is_ip_blocked("0.0.0.0") is True
    assert is_ip_blocked("::1") is True

def test_public_ips_allowed():
    # Public DNS like Cloudflare 1.1.1.1 or Google 8.8.8.8
    assert is_ip_blocked("1.1.1.1") is False
    assert is_ip_blocked("8.8.8.8") is False

def test_normalize_target():
    url, domain = normalize_target("example.com")
    assert url == "https://example.com"
    assert domain == "example.com"

    url2, domain2 = normalize_target("http://test.com/path")
    assert url2 == "http://test.com/path"
    assert domain2 == "test.com"

def test_reject_dangerous_schemes():
    with pytest.raises(ValueError, match="Unsupported protocol scheme"):
        normalize_target("file:///etc/passwd")

    with pytest.raises(ValueError, match="Unsupported protocol scheme"):
        normalize_target("gopher://127.0.0.1")

def test_reject_internal_hostnames():
    with pytest.raises(ValueError, match="Scanning internal or loopback hostname"):
        normalize_target("http://localhost:8000")

    with pytest.raises(ValueError, match="Scanning internal or loopback hostname"):
        normalize_target("http://metadata.google.internal")

def test_validate_target_security_blocks_private():
    with pytest.raises(ValueError):
        validate_target_security("127.0.0.1")

    with pytest.raises(ValueError):
        validate_target_security("192.168.0.1")
