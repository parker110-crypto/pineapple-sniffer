import pytest
from src.vpn_security_checks import VPNSecurityChecker

def test_detect_active_vpn():
    """
    Test VPN detection method.
    Note: This test might need to be adjusted based on actual system configuration.
    """
    result = VPNSecurityChecker.detect_active_vpn()
    # The result could be None or a dict with interface details
    assert result is None or isinstance(result, dict)

def test_check_ip_leak():
    """
    Test IP leak detection.
    This is a basic check and might require network connectivity.
    """
    result = VPNSecurityChecker.check_ip_leak()
    assert isinstance(result, bool)

def test_get_vpn_security_recommendations():
    """
    Test generation of VPN security recommendations.
    """
    recommendations = VPNSecurityChecker.get_vpn_security_recommendations()
    
    assert isinstance(recommendations, list)
    assert len(recommendations) > 0
    
    # Check that recommendations are strings
    assert all(isinstance(rec, str) for rec in recommendations)

    # Check some expected recommendation keywords
    expected_keywords = [
        'VPN', 'encryption', 'kill switch', 'protocol'
    ]
    
    for keyword in expected_keywords:
        assert any(keyword.lower() in rec.lower() for rec in recommendations)