import sys
import os
import json

# Add parent directory to python path if executing from within extractor directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from normalizer import normalize_URL
from extractor.scraper import get_soup
from extractor.wrapper import extract_full_website_report

def analyze_url(url: str):
    clean_url = normalize_URL(url)
    print(f"\n[+] Fetching and analyzing: {clean_url}")
    scrape_result = get_soup(clean_url)
    report = extract_full_website_report(clean_url, scrape_result)
    return report

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://www.wikipedia.org"
    report = analyze_url(target)
    print("\n" + "=" * 60)
    print(f"EXTRACTION REPORT FOR {report['domain']}")
    print("=" * 60)
    print(json.dumps(report, indent=2))
