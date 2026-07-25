import sys
import os
import re
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import Finding, Severity

# Pre-compiled regex patterns
URGENCY_REGEX = re.compile(r'(?i)\b(urgent|immediately|act now|verify your account|suspended|deactivated|will be closed|expire|limited time|within 24 hours|within 2 hours)\b')
SENSITIVE_INFO_REGEX = re.compile(r'(?i)\b(password|ssn|social security|credit card|bank account|otp|one-time|pin number)\b')
TOO_GOOD_REGEX = re.compile(r'(?i)\b(lottery|winner|prize|inheritance|million dollars|bitcoin|congratulations you have won)\b')
ATTACHMENT_REGEX = re.compile(r'(?i)(\.exe|\.scr|\.zip|\.rar|\.bat|\.cmd|\.vbs|\.js)\b')
GREETING_REGEX = re.compile(r'(?i)\b(dear customer|dear user|valued member|dear sir/madam)\b')

HTML_LINK_REGEX = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.IGNORECASE)
MD_LINK_REGEX = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'}

def extract_domain(email_addr: str) -> str:
    if '@' in email_addr:
        return email_addr.split('@')[-1].strip('>').strip().lower()
    return ''

def run_email_heuristics(text: str, sender: str = '', subject: str = '', headers: dict | None = None, homoglyph_findings: list = None) -> list[Finding]:
    findings = []
    if homoglyph_findings:
        findings.extend(homoglyph_findings)
        
    headers = headers or {}
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    sender_domain = extract_domain(sender)

    # 1. SPF/DKIM/DMARC failure
    try:
        auth_results = lower_headers.get('authentication-results', '').lower()
        if 'fail' in auth_results:
            findings.append(Finding(
                name='auth_failure',
                severity=Severity.CRITICAL,
                score_delta=30,
                reason='Email authentication (SPF/DKIM/DMARC) failed — sender may be spoofed'
            ))
    except Exception: pass

    # 2. Reply-To differs from From
    try:
        reply_to = lower_headers.get('reply-to', '')
        if sender and reply_to:
            reply_to_domain = extract_domain(reply_to)
            if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
                findings.append(Finding(
                    name='reply_to_mismatch',
                    severity=Severity.CRITICAL,
                    score_delta=25,
                    reason=f'Reply-To address ({reply_to_domain}) differs from sender ({sender_domain}) — replies would be routed to a different destination'
                ))
    except Exception: pass

    # 3. Display name vs sender mismatch
    try:
        if '<' in sender and '@' in sender:
            display_name = sender.split('<')[0].strip().lower()
            if display_name and sender_domain:
                # Basic check: if display name contains major brand but domain is freemail
                # More complex brand checks could be added here
                brands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix']
                freemail = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
                for brand in brands:
                    if brand in display_name and brand not in sender_domain and sender_domain in freemail:
                        findings.append(Finding(
                            name='display_name_mismatch',
                            severity=Severity.HIGH,
                            score_delta=20,
                            reason=f'Display name implies {brand} but sender domain is {sender_domain}'
                        ))
    except Exception: pass

    # Extract all URLs from body for further checks
    body_urls = []
    try:
        body_urls = URL_REGEX.findall(text)
    except Exception: pass

    # 4. Sender domain doesn't match link domains
    try:
        if body_urls and sender_domain:
            match_found = False
            for url in body_urls:
                parsed = urlparse(url)
                if parsed.hostname and (sender_domain in parsed.hostname or parsed.hostname in sender_domain):
                    match_found = True
                    break
            if not match_found:
                findings.append(Finding(
                    name='sender_link_mismatch',
                    severity=Severity.HIGH,
                    score_delta=15,
                    reason='Sender domain does not match any link domains in the email body'
                ))
    except Exception: pass

    # 5. Mismatched link text vs href
    try:
        for href, link_text in HTML_LINK_REGEX.findall(text):
            if '.' in link_text and ' ' not in link_text:  # Looks like a domain/URL
                href_host = urlparse(href).hostname or ''
                # Simple check if text looks like a URL but goes elsewhere
                if href_host and link_text.lower() not in href_host and href_host not in link_text.lower():
                    findings.append(Finding(
                        name='link_text_mismatch',
                        severity=Severity.HIGH,
                        score_delta=20,
                        reason=f'Visible link text suggests one destination but points to {href_host}'
                    ))
        
        for link_text, href in MD_LINK_REGEX.findall(text):
            if '.' in link_text and ' ' not in link_text:
                href_host = urlparse(href).hostname or ''
                if href_host and link_text.lower() not in href_host and href_host not in link_text.lower():
                    findings.append(Finding(
                        name='link_text_mismatch',
                        severity=Severity.HIGH,
                        score_delta=20,
                        reason=f'Visible link text suggests one destination but points to {href_host}'
                    ))
    except Exception: pass

    # 6. Urgency language
    try:
        matches = URGENCY_REGEX.findall(text)
        if matches:
            unique_matches = list(set([m.lower() for m in matches]))
            findings.append(Finding(
                name='urgency_language',
                severity=Severity.MEDIUM,
                score_delta=10,
                reason=f'Contains urgency/pressure language: "{", ".join(unique_matches)}"'
            ))
    except Exception: pass

    # 7. Request for sensitive info
    try:
        matches = SENSITIVE_INFO_REGEX.findall(text)
        if matches:
            unique_matches = list(set([m.lower() for m in matches]))
            findings.append(Finding(
                name='sensitive_info_request',
                severity=Severity.MEDIUM,
                score_delta=10,
                reason=f'Requests sensitive information: "{", ".join(unique_matches)}"'
            ))
    except Exception: pass

    # 8. Too-good-to-be-true
    try:
        matches = TOO_GOOD_REGEX.findall(text)
        if matches:
            unique_matches = list(set([m.lower() for m in matches]))
            findings.append(Finding(
                name='too_good_to_be_true',
                severity=Severity.MEDIUM,
                score_delta=10,
                reason=f'Contains too-good-to-be-true language: "{", ".join(unique_matches)}"'
            ))
    except Exception: pass

    # 9. Suspicious attachment mention
    try:
        matches = ATTACHMENT_REGEX.findall(text)
        if matches:
            unique_matches = list(set([m.lower() for m in matches]))
            findings.append(Finding(
                name='suspicious_attachment',
                severity=Severity.MEDIUM,
                score_delta=8,
                reason=f'Mentions suspicious attachment types: "{", ".join(unique_matches)}"'
            ))
    except Exception: pass

    # 10. URL shortener in body
    try:
        shorteners_found = []
        for url in body_urls:
            hostname = urlparse(url).hostname or ''
            if any(hostname.endswith(s) for s in SHORTENERS):
                shorteners_found.append(hostname)
        
        if shorteners_found:
            findings.append(Finding(
                name='shortener_in_body',
                severity=Severity.MEDIUM,
                score_delta=8,
                reason=f'Email body contains URL shorteners: {", ".join(set(shorteners_found))}'
            ))
    except Exception: pass

    # 11. Generic greeting
    try:
        if GREETING_REGEX.search(text):
            findings.append(Finding(
                name='generic_greeting',
                severity=Severity.LOW,
                score_delta=3,
                reason='Uses a generic greeting often found in mass phishing emails'
            ))
    except Exception: pass

    # 12. All-caps subject
    try:
        if subject and len(subject) > 5:
            alpha_chars = [c for c in subject if c.isalpha()]
            if alpha_chars:
                upper_chars = [c for c in alpha_chars if c.isupper()]
                if len(upper_chars) / len(alpha_chars) > 0.7:
                    findings.append(Finding(
                        name='allcaps_subject',
                        severity=Severity.LOW,
                        score_delta=2,
                        reason='Subject line is mostly capitalized'
                    ))
    except Exception: pass

    return findings

def collect_email_safe_signals(text: str, sender: str, headers: dict | None) -> list[str]:
    signals = []
    headers = headers or {}
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    try:
        auth_results = lower_headers.get('authentication-results', '').lower()
        if 'pass' in auth_results and 'fail' not in auth_results:
            signals.append('Email authentication (SPF/DKIM/DMARC) passed')
    except Exception: pass
    
    return signals
