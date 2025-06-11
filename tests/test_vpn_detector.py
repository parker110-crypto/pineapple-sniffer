import pytest
from src.vpn_detector import VPNDetector
import platform

class TestVPNDetector:
    def test_detect_vpn_connections_basic(self):
        """Basic test to ensure VPN detection method works."""
        result = VPNDetector.detect_vpn_connections()
        
        # Check basic structure of result
        assert 'status' in result
        
        # Status should be one of these values
        assert result['status'] in ['success', 'error', 'unsupported_os']
    
    def test_security_recommendations(self):
        """Test security recommendations generation."""
        result = VPNDetector.detect_vpn_connections()
        
        # If successful, validate recommendations
        if result['status'] == 'success':
            assert 'security_recommendations' in result
            recommendations = result['security_recommendations']
            
            # Verify recommendations are meaningful
            assert len(recommendations) > 0
            assert all(isinstance(rec, str) for rec in recommendations)
    
    def test_error_handling(self):
        """Verify proper error handling for VPN detection."""
        result = VPNDetector.detect_vpn_connections()
        
        # Check that error messages are clear when detection fails
        if result['status'] == 'error':
            assert 'message' in result
            assert isinstance(result['message'], str)
            assert len(result['message']) > 0