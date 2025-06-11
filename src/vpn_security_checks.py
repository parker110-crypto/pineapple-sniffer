import subprocess
import re
from typing import Dict, Optional, List

class VPNSecurityChecker:
    """
    A comprehensive VPN security checking utility.
    Performs various security checks on VPN configurations.
    """

    @staticmethod
    def detect_active_vpn() -> Optional[Dict[str, str]]:
        """
        Detect active VPN connections across different platforms.
        
        Returns:
            Dict with VPN connection details or None if no VPN detected
        """
        try:
            # Check for active network interfaces that suggest VPN
            result = subprocess.run(
                ['ip', 'addr'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            # Look for common VPN interface patterns
            vpn_patterns = [
                r'tun\d+',   # OpenVPN typical interface
                r'wg\d+',    # WireGuard interface
                r'ppp\d+',   # PPTP/L2TP interface
            ]
            
            for pattern in vpn_patterns:
                match = re.search(pattern, result.stdout)
                if match:
                    return {
                        'interface': match.group(0),
                        'protocol': 'Unknown'
                    }
            
            return None
        
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    @staticmethod
    def check_ip_leak() -> bool:
        """
        Check if VPN is effectively masking true IP.
        
        Returns:
            bool: True if no IP leak detected, False otherwise
        """
        try:
            # Use external IP check service
            result = subprocess.run(
                ['curl', '-s', 'https://api.ipify.org'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            # Validate IP format
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            return bool(re.match(ip_pattern, result.stdout.strip()))
        
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def get_vpn_security_recommendations() -> List[str]:
        """
        Generate security recommendations for VPN usage.
        
        Returns:
            List of security recommendation strings
        """
        recommendations = [
            "Use OpenVPN or WireGuard protocols",
            "Enable kill switch in VPN client",
            "Use strong encryption (AES-256)",
            "Avoid free VPN services",
            "Regularly update VPN client software"
        ]
        return recommendations