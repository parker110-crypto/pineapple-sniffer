import subprocess
import re
import platform
from typing import Dict, Optional, List

class VPNSecurityChecker:
    """
    A comprehensive VPN security detection and analysis class.
    
    Provides methods to detect and analyze VPN connections across different platforms.
    """
    
    @staticmethod
    def detect_vpn_connection() -> Dict[str, str]:
        """
        Detect active VPN connections based on the operating system.
        
        Returns:
            A dictionary with VPN connection details or an empty dict if no VPN is detected.
        """
        os_type = platform.system().lower()
        
        try:
            if os_type == 'darwin':  # macOS
                return VPNSecurityChecker._detect_vpn_macos()
            elif os_type == 'linux':
                return VPNSecurityChecker._detect_vpn_linux()
            else:
                return {}
        except Exception as e:
            print(f"Error detecting VPN connection: {e}")
            return {}
    
    @staticmethod
    def _detect_vpn_macos() -> Dict[str, str]:
        """Detect VPN connections on macOS."""
        try:
            result = subprocess.run(['netstat', '-nr'], capture_output=True, text=True)
            vpn_routes = [line for line in result.stdout.split('\n') if 'utun' in line]
            
            if vpn_routes:
                return {
                    'status': 'connected',
                    'interface': 'utun',
                    'platform': 'macOS'
                }
        except Exception:
            pass
        
        return {}
    
    @staticmethod
    def _detect_vpn_linux() -> Dict[str, str]:
        """Detect VPN connections on Linux."""
        try:
            result = subprocess.run(['ip', 'tuntap'], capture_output=True, text=True)
            vpn_interfaces = [line for line in result.stdout.split('\n') if 'tun' in line]
            
            if vpn_interfaces:
                return {
                    'status': 'connected',
                    'interface': 'tun',
                    'platform': 'Linux'
                }
        except Exception:
            pass
        
        return {}
    
    @staticmethod
    def analyze_vpn_security(connection_info: Dict[str, str]) -> List[str]:
        """
        Analyze VPN connection security and provide recommendations.
        
        Args:
            connection_info: Dictionary containing VPN connection details
        
        Returns:
            A list of security recommendations
        """
        if not connection_info:
            return ['No VPN connection detected']
        
        recommendations = []
        
        # Example security checks
        if connection_info.get('platform') == 'macOS':
            recommendations.append('Verify macOS VPN configuration settings')
        elif connection_info.get('platform') == 'Linux':
            recommendations.append('Check Linux VPN tunneling protocol')
        
        return recommendations