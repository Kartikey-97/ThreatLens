from urllib.parse import urlparse

def normalize_URL(url: str) -> str:
    """
    Ensures URL has a valid http:// or https:// scheme and is trimmed.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_domain(url: str) -> str:
    """
    Extracts the clean domain name (hostname) without protocol or path.
    Example: 'https://sub.example.com/page' -> 'sub.example.com'
    """
    url = normalize_URL(url)
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    return hostname.lower()
