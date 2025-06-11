import pytest
from src.vpn_security.cli import parse_vpn_args

def test_default_no_args():
    """Test parsing with no arguments."""
    args = parse_vpn_args([])
    assert args.protocol is None
    assert not args.detect_leak
    assert not args.config_check
    assert not args.verbose

def test_protocol_argument():
    """Test parsing with protocol argument."""
    for protocol in ['openvpn', 'wireguard', 'ipsec']:
        args = parse_vpn_args(['--protocol', protocol])
        assert args.protocol == protocol

def test_detect_leak_argument():
    """Test leak detection argument."""
    args = parse_vpn_args(['--detect-leak'])
    assert args.detect_leak

def test_config_check_argument():
    """Test config check argument."""
    args = parse_vpn_args(['--config-check'])
    assert args.config_check

def test_verbose_argument():
    """Test verbose argument."""
    args = parse_vpn_args(['-v'])
    assert args.verbose
    
    args = parse_vpn_args(['--verbose'])
    assert args.verbose

def test_invalid_protocol():
    """Test invalid protocol raises an error."""
    with pytest.raises(SystemExit):
        parse_vpn_args(['--protocol', 'invalid_protocol'])