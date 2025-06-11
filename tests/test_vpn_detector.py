import pytest
from src.vpn_detector import VPNDetector
import platform

class TestVPNDetector:
    def test_detect_vpn_connections_basic(self):
        """Basic test to ensure VPN detection method works."""
        result = VPNDetector.detect_vpn_connections()
        
        # Check basic structure of result
        assert 'status' in result
        assert 'os' in result
        
        # Check for valid status
        assert result['status'] in ['success', 'error', 'unsupported_os']
    
    def test_security_recommendations(self):
        """Test security recommendations generation."""
        result = VPNDetector.detect_vpn_connections()
        
        if result['status'] == 'success':
            assert 'security_recommendations' in result
            recommendations = result['security_recommendations']
            
            # Verify recommendations are meaningful
            assert len(recommendations) > 0
            assert all(isinstance(rec, str) for rec in recommendations)
    
    def test_os_detection(self):
        """Verify correct OS detection."""
        result = VPNDetector.detect_vpn_connections()
        
        current_os = platform.system().lower()
        if current_os in ['darwin', 'linux']:
            assert result['os'] == current_os
        else:
            assert result['status'] == 'unsupported_os'