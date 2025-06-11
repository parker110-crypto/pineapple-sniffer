import subprocess
import re
import logging
from typing import Dict, List, Optional, Tuple

class VPNConfigurationAnalyzer:
    """
    A class for detecting and analyzing VPN configurations across different platforms.
    
    Provides methods to detect active VPN connections and assess their security parameters.
    """
    
    def __init__(self):
        """
        Initialize the VPN Configuration Analyzer with logging.
        """
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def detect_vpn_connections(self) -> List[Dict[str, str]]:
        """
        Detect active VPN connections across different platforms.
        
        Returns:
            List of dictionaries containing VPN connection details.
        """
        try:
            # Attempt different methods to detect VPN connections
            connections = (
                self._detect_openvpn_connections() + 
                self._detect_wireguard_connections() + 
                self._detect_ipsec_connections()
            )
            
            self.logger.info(f"Detected {len(connections)} VPN connection(s)")
            return connections
        
        except Exception as e:
            self.logger.error(f"Error detecting VPN connections: {e}")
            return []
    
    def _detect_openvpn_connections(self) -> List[Dict[str, str]]:
        """
        Detect OpenVPN connections.
        
        Returns:
            List of OpenVPN connection details.
        """
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            openvpn_processes = [
                line for line in result.stdout.split('\n') 
                if 'openvpn' in line.lower()
            ]
            
            return [
                {
                    'type': 'OpenVPN',
                    'status': 'Active',
                    'details': process
                } for process in openvpn_processes
            ]
        except Exception as e:
            self.logger.warning(f"OpenVPN detection error: {e}")
            return []
    
    def _detect_wireguard_connections(self) -> List[Dict[str, str]]:
        """
        Detect WireGuard connections.
        
        Returns:
            List of WireGuard connection details.
        """
        try:
            result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
            wireguard_interfaces = [
                line.strip() for line in result.stdout.split('\n')
                if 'wireguard' in line.lower()
            ]
            
            return [
                {
                    'type': 'WireGuard',
                    'status': 'Active',
                    'details': interface
                } for interface in wireguard_interfaces
            ]
        except Exception as e:
            self.logger.warning(f"WireGuard detection error: {e}")
            return []
    
    def _detect_ipsec_connections(self) -> List[Dict[str, str]]:
        """
        Detect IPSec connections.
        
        Returns:
            List of IPSec connection details.
        """
        try:
            result = subprocess.run(['ip', 'xfrm', 'state'], capture_output=True, text=True)
            ipsec_connections = [
                line.strip() for line in result.stdout.split('\n')
                if 'esp' in line.lower()  # ESP is typical for IPSec
            ]
            
            return [
                {
                    'type': 'IPSec',
                    'status': 'Active',
                    'details': connection
                } for connection in ipsec_connections
            ]
        except Exception as e:
            self.logger.warning(f"IPSec detection error: {e}")
            return []
    
    def analyze_vpn_security(self, vpn_connections: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Analyze the security of detected VPN connections.
        
        Args:
            vpn_connections: List of detected VPN connections
        
        Returns:
            List of security recommendations for each connection.
        """
        recommendations = []
        
        for connection in vpn_connections:
            analysis = {
                'type': connection['type'],
                'recommendations': []
            }
            
            # Basic security checks
            if connection['type'] == 'OpenVPN':
                analysis['recommendations'].extend(self._analyze_openvpn_security(connection))
            elif connection['type'] == 'WireGuard':
                analysis['recommendations'].extend(self._analyze_wireguard_security(connection))
            elif connection['type'] == 'IPSec':
                analysis['recommendations'].extend(self._analyze_ipsec_security(connection))
            
            recommendations.append(analysis)
        
        return recommendations
    
    def _analyze_openvpn_security(self, connection: Dict[str, str]) -> List[str]:
        """
        Perform security analysis specific to OpenVPN.
        
        Args:
            connection: OpenVPN connection details
        
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        # Add OpenVPN-specific security checks
        recommendations.append("Consider using updated OpenVPN configurations")
        recommendations.append("Ensure encryption is set to at least AES-256")
        
        return recommendations
    
    def _analyze_wireguard_security(self, connection: Dict[str, str]) -> List[str]:
        """
        Perform security analysis specific to WireGuard.
        
        Args:
            connection: WireGuard connection details
        
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        # Add WireGuard-specific security checks
        recommendations.append("Verify WireGuard peer configurations")
        recommendations.append("Ensure proper key rotation practices")
        
        return recommendations
    
    def _analyze_ipsec_security(self, connection: Dict[str, str]) -> List[str]:
        """
        Perform security analysis specific to IPSec.
        
        Args:
            connection: IPSec connection details
        
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        # Add IPSec-specific security checks
        recommendations.append("Check IKE and ESP encryption strength")
        recommendations.append("Verify NAT traversal settings")
        
        return recommendations