import pytest
from src.vpn_security_checker import VPNSecurityChecker

def test_vpn_security_checker_initialization():
    """Test the VPN security checker can be initialized."""
    checker = VPNSecurityChecker()
    assert checker is not None

def test_detect_vpn_connection():
    """Test VPN connection detection method."""
    connection_info = VPNSecurityChecker.detect_vpn_connection()
    assert isinstance(connection_info, dict)

def test_analyze_vpn_security():
    """Test VPN security analysis method."""
    # Test with empty connection
    recommendations = VPNSecurityChecker.analyze_vpn_security({})
    assert recommendations == ['No VPN connection detected']
    
    # Test with mock connection
    mock_connection = {
        'status': 'connected',
        'interface': 'utun',
        'platform': 'macOS'
    }
    recommendations = VPNSecurityChecker.analyze_vpn_security(mock_connection)
    assert len(recommendations) > 0
    assert any('macOS' in rec for rec in recommendations)

def test_macos_vpn_detection():
    """Test macOS specific VPN detection."""
    connection = VPNSecurityChecker._detect_vpn_macos()
    assert isinstance(connection, dict)

def test_linux_vpn_detection():
    """Test Linux specific VPN detection."""
    connection = VPNSecurityChecker._detect_vpn_linux()
    assert isinstance(connection, dict)