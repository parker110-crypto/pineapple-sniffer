import pytest
import sys
import os

# Add the project's src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from vpn_analyzer import VPNConfigurationAnalyzer

def test_vpn_configuration_analyzer_initialization():
    """
    Test that the VPNConfigurationAnalyzer can be initialized.
    """
    analyzer = VPNConfigurationAnalyzer()
    assert analyzer is not None

def test_detect_vpn_connections_returns_list():
    """
    Test that detect_vpn_connections returns a list.
    """
    analyzer = VPNConfigurationAnalyzer()
    connections = analyzer.detect_vpn_connections()
    assert isinstance(connections, list)

def test_analyze_vpn_security_returns_recommendations():
    """
    Test that analyze_vpn_security returns meaningful recommendations.
    """
    analyzer = VPNConfigurationAnalyzer()
    
    # Create a mock VPN connection
    mock_connections = [
        {'type': 'OpenVPN', 'status': 'Active', 'details': 'Mock OpenVPN'},
        {'type': 'WireGuard', 'status': 'Active', 'details': 'Mock WireGuard'}
    ]
    
    recommendations = analyzer.analyze_vpn_security(mock_connections)
    
    assert isinstance(recommendations, list)
    assert len(recommendations) == len(mock_connections)
    
    for analysis in recommendations:
        assert 'type' in analysis
        assert 'recommendations' in analysis
        assert len(analysis['recommendations']) > 0

def test_openvpn_security_analysis():
    """
    Test OpenVPN-specific security analysis recommendations.
    """
    analyzer = VPNConfigurationAnalyzer()
    mock_connection = {'type': 'OpenVPN', 'status': 'Active', 'details': 'Mock OpenVPN'}
    
    recommendations = analyzer._analyze_openvpn_security(mock_connection)
    
    assert "Consider using updated OpenVPN configurations" in recommendations
    assert "Ensure encryption is set to at least AES-256" in recommendations

def test_wireguard_security_analysis():
    """
    Test WireGuard-specific security analysis recommendations.
    """
    analyzer = VPNConfigurationAnalyzer()
    mock_connection = {'type': 'WireGuard', 'status': 'Active', 'details': 'Mock WireGuard'}
    
    recommendations = analyzer._analyze_wireguard_security(mock_connection)
    
    assert "Verify WireGuard peer configurations" in recommendations
    assert "Ensure proper key rotation practices" in recommendations