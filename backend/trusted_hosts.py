"""
Trusted hosts management - IP prefix validation and access control.
"""
import ipaddress
from typing import Optional, List


def parse_trusted_hosts(trusted_hosts_str: Optional[str]) -> List[ipaddress.IPv4Network]:
    """
    Parse comma-separated IP prefixes into a list of IPv4Network objects.
    Returns empty list if None or empty string.
    """
    if not trusted_hosts_str:
        return []
    
    networks = []
    for prefix in trusted_hosts_str.split(','):
        prefix = prefix.strip()
        if not prefix:
            continue
        try:
            # Parse as network (supports both single IPs and prefixes)
            networks.append(ipaddress.IPv4Network(prefix, strict=False))
        except (ipaddress.AddressValueError, ValueError):
            # Skip invalid entries silently (or could raise ValidationError)
            pass
    return networks


def validate_trusted_hosts_format(trusted_hosts_str: str) -> Optional[str]:
    """
    Validate the format of trusted hosts string.
    Returns error message if invalid, None if valid.
    """
    if not trusted_hosts_str or not trusted_hosts_str.strip():
        # Empty is valid - means no restrictions
        return None
    
    prefixes = [p.strip() for p in trusted_hosts_str.split(',') if p.strip()]
    
    if not prefixes:
        return None
    
    for prefix in prefixes:
        try:
            # Try to parse as network
            ipaddress.IPv4Network(prefix, strict=False)
        except (ipaddress.AddressValueError, ValueError) as e:
            return f"Invalid IP prefix '{prefix}': {str(e)}"
    
    return None


def is_ip_allowed(client_ip: str, trusted_hosts_str: Optional[str]) -> bool:
    """
    Check if a client IP is allowed based on trusted hosts configuration.
    
    If trusted_hosts_str is None or empty, any IP is allowed (no restrictions).
    Otherwise, the client IP must be within one of the configured prefixes.
    """
    if not trusted_hosts_str or not trusted_hosts_str.strip():
        # No restrictions
        return True
    
    try:
        client_addr = ipaddress.IPv4Address(client_ip)
    except (ipaddress.AddressValueError, ValueError):
        # Invalid client IP format
        return False
    
    networks = parse_trusted_hosts(trusted_hosts_str)
    if not networks:
        # No valid networks configured, allow access
        return True
    
    # Check if client IP is in any of the allowed networks
    for network in networks:
        if client_addr in network:
            return True
    
    return False


def format_trusted_hosts_list(trusted_hosts_str: Optional[str]) -> List[str]:
    """
    Parse and return a clean list of trusted host prefixes for display.
    """
    if not trusted_hosts_str:
        return []
    
    networks = parse_trusted_hosts(trusted_hosts_str)
    return [str(net) for net in networks]
