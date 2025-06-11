import subprocess
import re
import platform
from typing import Dict, List, Optional

class VPNDetector:
    """
    A class to detect and analyze VPN configurations across different platforms.
    
    Supports detection of VPN connections and provides security recommendations.
    """

    @staticmethod
    def detect_vpn_connections() -> List[Dict[str, str]]:
        """
        Detect active VPN connections across different platforms.
        
        Returns:
            List of dictionaries containing VPN connection details.
        """
        os_type = platform.system().lower()
        
        try:
            if os_type == 'darwin':  # macOS
                return VPNDetector._detect_vpn_macos()
            elif os_type == 'linux':
                return VPNDetector._detect_vpn_linux()
            else:
                return []
        except Exception as e:
            print(f"Error detecting VPN connections: {e}")
            return []

    @staticmethod
    def _detect_vpn_macos() -> List[Dict[str, str]]:
        """
        Detect VPN connections on macOS.
        
        Returns:
            List of active VPN connection details.
        """
        try:
            # Use scutil to get VPN connection details
            result = subprocess.run(['scutil', '--nc', 'list'], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=5)
            
            vpn_connections = []
            for line in result.stdout.splitlines():
                # Look for VPN connections in the output
                match = re.search(r'\(.*\)\s*(.+)', line)
                if match:
                    vpn_connections.append({
                        'name': match.group(1),
                        'platform': 'macOS'
                    })
            
            return vpn_connections
        except Exception as e:
            print(f"macOS VPN detection error: {e}")
            return []

    @staticmethod
    def _detect_vpn_linux() -> List[Dict[str, str]]:
        """
        Detect VPN connections on Linux.
        
        Returns:
            List of active VPN connection details.
        """
        try:
            # Use nmcli to get VPN connection details
            result = subprocess.run(['nmcli', '-t', '-f', 'NAME,TYPE,STATE', 'con', 'show'], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=5)
            
            vpn_connections = []
            for line in result.stdout.splitlines():
                # Look for VPN connections in the output
                parts = line.split(':')
                if len(parts) >= 3 and 'vpn' in parts[1].lower() and 'activated' in parts[2].lower():
                    vpn_connections.append({
                        'name': parts[0],
                        'platform': 'Linux'
                    })
            
            return vpn_connections
        except Exception as e:
            print(f"Linux VPN detection error: {e}")
            return []

    @staticmethod
    def analyze_vpn_security(connection: Dict[str, str]) -> Dict[str, str]:
        """
        Analyze the security of a VPN connection.
        
        Args:
            connection: A dictionary containing VPN connection details.
        
        Returns:
            A dictionary of security recommendations.
        """
        recommendations = {
            'encryption': 'Verify strong encryption (AES-256)',
            'protocol': 'Prefer OpenVPN or WireGuard',
            'authentication': 'Use multi-factor authentication',
            'dns_leak': 'Check for DNS leak protection',
            'kill_switch': 'Enable network kill switch'
        }
        
        return recommendations

def main():
    """
    Main function to demonstrate VPN detection and analysis.
    """
    vpn_connections = VPNDetector.detect_vpn_connections()
    
    if not vpn_connections:
        print("No VPN connections detected.")
        return
    
    for connection in vpn_connections:
        print(f"Detected VPN Connection: {connection}")
        security_analysis = VPNDetector.analyze_vpn_security(connection)
        print("Security Recommendations:")
        for key, recommendation in security_analysis.items():
            print(f"- {key.replace('_', ' ').title()}: {recommendation}")

if __name__ == "__main__":
    main()