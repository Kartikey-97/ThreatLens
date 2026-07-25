import re
from urllib.parse import urlparse
from typing import Dict, Any, List

def evaluate_website_safety(url: str, headers: Dict[str, str], soup, html_text: str, ssl_info: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = 0
    risk_flags = []
    parsed_url = urlparse(url)

    # 1. Check Protocol & SSL
    if parsed_url.scheme != "https":
        risk_score += 30
        risk_flags.append("Missing HTTPS encryption (Insecure HTTP protocol)")
    
    if ssl_info.get("has_ssl") and not ssl_info.get("is_valid"):
        risk_score += 40
        risk_flags.append("SSL Certificate is invalid or expired")

    # 2. Check Security Headers
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    security_headers = {
        "strict-transport-security": ("HSTS Header missing", 10),
        "x-frame-options": ("X-Frame-Options header missing (Clickjacking risk)", 5),
        "content-security-policy": ("Content-Security-Policy (CSP) missing", 5),
        "x-content-type-options": ("X-Content-Type-Options missing", 5)
    }

    missing_headers = []
    for header, (warning_msg, points) in security_headers.items():
        if header not in headers_lower:
            missing_headers.append(header)
            risk_score += points

    if len(missing_headers) == len(security_headers):
        risk_flags.append("No standard HTTP Security Headers detected")
    elif missing_headers:
        risk_flags.append(f"Missing security headers: {', '.join(missing_headers)}")

    # 3. Form & Phishing Inspection
    if soup:
        # Password inputs over HTTP
        password_inputs = soup.find_all("input", attrs={"type": "password"})
        if password_inputs and parsed_url.scheme != "https":
            risk_score += 50
            risk_flags.append("CRITICAL: Password input field found on unencrypted HTTP page!")

        # Form actions pointing to external domains
        forms = soup.find_all("form", action=True)
        for form in forms:
            action = form['action'].strip()
            if action.startswith(("http://", "https://")):
                action_domain = urlparse(action).netloc.split(':')[0]
                host_domain = parsed_url.netloc.split(':')[0]
                if action_domain and host_domain and action_domain.lower() != host_domain.lower():
                    risk_score += 30
                    risk_flags.append(f"Form submits data to external third-party domain ({action_domain})")

    # 4. Obfuscated JavaScript & Suspicious Scripting
    if html_text:
        html_lower = html_text.lower()
        if "eval(unescape(" in html_lower or "eval(function(p,a,c,k,e,d)" in html_lower:
            risk_score += 25
            risk_flags.append("Obfuscated JavaScript detected (eval/unescape pattern)")

        if "<meta http-equiv=\"refresh\"" in html_lower:
            risk_score += 15
            risk_flags.append("Automatic META HTTP refresh redirect detected")

    # 5. Phishing Keyword Patterns
    if html_text:
        phishing_phrases = [
            "verify your bank account",
            "account suspended immediately",
            "confirm your credit card",
            "urgent security update required",
            "unusual login activity detected"
        ]
        for phrase in phishing_phrases:
            if phrase in html_text.lower():
                risk_score += 20
                risk_flags.append(f"Phishing keyword detected: '{phrase}'")
                break

    # Cap risk score between 0 and 100
    final_score = min(max(risk_score, 0), 100)

    # Classify safety status
    if final_score <= 20:
        safety_status = "SAFE"
    elif final_score <= 50:
        safety_status = "SUSPICIOUS"
    else:
        safety_status = "UNSAFE"

    return {
        "safety_status": safety_status,
        "risk_score": final_score,
        "safety_rating": f"{100 - final_score}/100",
        "threat_flags": risk_flags
    }
