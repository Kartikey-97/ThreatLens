import re
from urllib.parse import urljoin
from typing import List, Dict


def extract_emails(html_text: str) -> List[str]:
    """
    Extract email addresses from HTML.
    """
    if not html_text:
        return []

    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    found = re.findall(email_pattern, html_text)

    ignored_extensions = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".pdf", ".css", ".js", ".woff", ".ttf"
    )

    clean_emails = set()

    for email in found:
        email = email.lower()

        if email.endswith(ignored_extensions):
            continue

        if len(email) > 100:
            continue

        clean_emails.add(email)

    return sorted(clean_emails)


def extract_social_links(soup, base_url: str) -> Dict[str, List[str]]:
    """
    Extract social media profile links from <a> tags.
    """

    social_platforms = {
        "linkedin": ["linkedin.com/company", "linkedin.com/in", "linkedin.com/pub"],
        "twitter": ["twitter.com", "x.com"],
        "facebook": ["facebook.com", "fb.com"],
        "instagram": ["instagram.com"],
        "youtube": ["youtube.com", "youtu.be"],
        "github": ["github.com"],
        "pinterest": ["pinterest.com"],
    }

    found_socials = {
        platform: []
        for platform in social_platforms
    }

    if not soup:
        return {}

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()

        if href.startswith("/"):
            href = urljoin(base_url, href)

        href_lower = href.lower()

        for platform, domains in social_platforms.items():
            if any(domain in href_lower for domain in domains):
                if href not in found_socials[platform]:
                    found_socials[platform].append(href)

    return {
        platform: links
        for platform, links in found_socials.items()
        if links
    }