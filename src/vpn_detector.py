import subprocess
import json
from typing import Dict, List, Optional, Any
import platform
import re

class VPNDetector:
    """
    A comprehensive VPN configuration detection and analysis tool.
    
    Supports detection of VPN connections across different operating systems.
    Provides security recommendations based on VPN configuration.
    """
    
    @staticmethod
    def detect_vpn_connections() -> Dict[str, Any]:
        """
        Detect active VPN connections across different platforms.
        
        Returns:
            Dict containing VPN connection details and security analysis.
        """
        os_name = platform.system().lower()
        
        if os_name == 'darwin':  # macOS
            return VPNDetector._detect_macos_vpn()
        elif os_name == 'linux':
            return VPNDetector._detect_linux_vpn()
        else:
            return {
                'status': 'unsupported_os',
                'message': f'VPN detection not supported on {os_name}'
            }
    
    @staticmethod
    def _detect_macos_vpn() -> Dict[str, Any]:
        """Detect VPN connections on macOS."""
        try:
            # Use scutil to get VPN details
            result = subprocess.run(
                ['scutil', '--nc', 'list'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            vpn_connections = result.stdout.strip().split('\n')
            
            # Basic parsing of VPN connections
            parsed_connections = [
                conn for conn in vpn_connections 
                if 'VPN' in conn or 'IPSec' in conn
            ]
            
            return {
                'status': 'success',
                'os': 'macos',
                'vpn_connections': parsed_connections,
                'security_recommendations': VPNDetector._analyze_vpn_security(parsed_connections)
            }
        except subprocess.TimeoutExpired:
            return {
                'status': 'error',
                'message': 'VPN detection timed out'
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'VPN detection failed: {str(e)}'
            }
    
    @staticmethod
    def _detect_linux_vpn() -> Dict[str, Any]:
        """Detect VPN connections on Linux."""
        try:
            # Check network interfaces for typical VPN indicators
            result = subprocess.run(
                ['ip', 'addr'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            # Look for common VPN interface patterns
            vpn_interfaces = re.findall(
                r'(tun\d+|ppp\d+|wg\d+)', 
                result.stdout
            )
            
            return {
                'status': 'success', 
                'os': 'linux',
                'vpn_connections': vpn_interfaces,
                'security_recommendations': VPNDetector._analyze_vpn_security(vpn_interfaces)
            }
        except subprocess.TimeoutExpired:
            return {
                'status': 'error',
                'message': 'VPN interface detection timed out'
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'VPN interface detection failed: {str(e)}'
            }
    
    @staticmethod
    def _analyze_vpn_security(connections: List[str]) -> List[str]:
        """
        Analyze security of detected VPN connections.
        
        Args:
            connections: List of detected VPN connections
        
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        if not connections:
            recommendations.append(
                "No VPN connections detected. Consider using a VPN for enhanced privacy."
            )
        else:
            recommendations.append(
                f"Found {len(connections)} VPN connection(s). Verify connection security."
            )
            
            # Add more specific security checks
            recommendations.extend([
                "Ensure VPN uses strong encryption (AES-256 or better)",
                "Use OpenVPN or WireGuard protocols when possible",
                "Disable split tunneling for maximum security",
                "Always use a kill switch to prevent IP leaks"
            ])
        
        return recommendations

# Optional main block for direct script execution
if __name__ == '__main__':
    result = VPNDetector.detect_vpn_connections()
    print(json.dumps(result, indent=2))