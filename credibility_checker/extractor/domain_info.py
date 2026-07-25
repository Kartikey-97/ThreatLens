import socket
import ssl
import datetime
import requests
from typing import Dict, Any, Optional
from normalizer import extract_domain

def get_ip_address(hostname: str) -> Optional[str]:
    """
    Performs DNS resolution to get IPv4 address of host.
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def get_server_location(ip_address: str) -> Dict[str, Any]:
    """
    Retrieves geolocation information for an IP address using ip-api.com.
    """
    if not ip_address:
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,isp,org,as"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown")
                }
    except Exception:
        pass

    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}


def get_ssl_certificate_info(hostname: str) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                
                # Expiry and Effective Date parsing
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")
                expiry_date = None
                issued_date = None
                is_valid = False
                days_remaining = 0
                
                if not_after:
                    expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry_date = expiry_dt.strftime("%Y-%m-%d")
                    now = datetime.datetime.utcnow()
                    days_remaining = (expiry_dt - now).days
                    is_valid = days_remaining > 0

                if not_before:
                    issued_dt = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    issued_date = issued_dt.strftime("%Y-%m-%d")

                # Extract Issuer Details
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

                # Extract Subject Details & SANs (Subject Alternative Names)
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                san_list = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

                return {
                    "has_ssl": True,
                    "is_valid": is_valid,
                    "issuer": issuer,
                    "common_name": subject_dict.get("commonName"),
                    "issued_date": issued_date,
                    "expiry_date": expiry_date,
                    "days_remaining": days_remaining,
                    "tls_version": tls_version,
                    "cipher_suite": cipher[0] if cipher else None,
                    "serial_number": cert.get("serialNumber"),
                    "subject_alternative_names": san_list[:10]  # Top 10 SAN domains
                }
    except Exception as e:
        return {
            "has_ssl": False,
            "is_valid": False,
            "issuer": None,
            "common_name": None,
            "issued_date": None,
            "expiry_date": None,
            "days_remaining": 0,
            "tls_version": None,
            "cipher_suite": None,
            "serial_number": None,
            "subject_alternative_names": [],
            "error": str(e)
        }


def get_domain_creation_date(domain: str) -> Dict[str, Any]:
    """
    Fetches domain creation date and registrar using python-whois with RDAP API fallback.
    """
    domain = extract_domain(domain)
    
    # 1. Try RDAP REST API
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        res = requests.get(rdap_url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") in ["registration", "created"]:
                    event_date = event.get("eventDate")
                    if event_date:
                        date_str = event_date.split("T")[0]
                        return {"creation_date": date_str, "source": "RDAP"}
    except Exception:
        pass

    # 2. Try python-whois package
    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, datetime.datetime):
            date_str = creation_date.strftime("%Y-%m-%d")
            return {"creation_date": date_str, "source": "WHOIS"}
        elif creation_date:
            return {"creation_date": str(creation_date).split()[0], "source": "WHOIS"}
    except Exception:
        pass

    return {"creation_date": "Unknown / Redacted", "source": "None"}
