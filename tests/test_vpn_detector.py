import pytest
import platform
from unittest.mock import patch
from src.vpn_detector import VPNDetector

class TestVPNDetector:
    def test_detect_vpn_connections_no_vpn(self):
        """
        Test VPN detection when no VPN is connected.
        """
        with patch.object(platform, 'system', return_value='Linux'), \
             patch('subprocess.run') as mock_run:
            # Simulate no VPN connections
            mock_run.return_value.stdout = ''
            
            connections = VPNDetector.detect_vpn_connections()
            assert len(connections) == 0

    @pytest.mark.skipif(platform.system() != 'Darwin', reason="macOS specific test")
    def test_detect_vpn_connections_macos(self):
        """
        Test VPN detection on macOS.
        """
        with patch('subprocess.run') as mock_run:
            # Simulate a VPN connection
            mock_run.return_value.stdout = '(Connected) MyVPN\n'
            
            connections = VPNDetector.detect_vpn_connections()
            assert len(connections) > 0
            assert connections[0]['name'] == 'MyVPN'
            assert connections[0]['platform'] == 'macOS'

    @pytest.mark.skipif(platform.system() != 'Linux', reason="Linux specific test")
    def test_detect_vpn_connections_linux(self):
        """
        Test VPN detection on Linux.
        """
        with patch('subprocess.run') as mock_run:
            # Simulate a VPN connection
            mock_run.return_value.stdout = 'MyVPN:vpn:activated\n'
            
            connections = VPNDetector.detect_vpn_connections()
            assert len(connections) > 0
            assert connections[0]['name'] == 'MyVPN'
            assert connections[0]['platform'] == 'Linux'

    def test_analyze_vpn_security(self):
        """
        Test VPN security analysis.
        """
        connection = {'name': 'TestVPN', 'platform': 'Linux'}
        recommendations = VPNDetector.analyze_vpn_security(connection)
        
        expected_keys = [
            'encryption', 
            'protocol', 
            'authentication', 
            'dns_leak', 
            'kill_switch'
        ]
        
        for key in expected_keys:
            assert key in recommendations
            assert isinstance(recommendations[key], str)
            assert len(recommendations[key]) > 0