import sys
import json
import argparse
from normalizer import normalize_URL
from extractor.scraper import get_soup
from extractor.wrapper import extract_full_website_report

def run_scraper(urls):
    results = []
    for raw_url in urls:
        clean_url = normalize_URL(raw_url)
        print(f"\n[+] Analyzing: {clean_url} ...")
        scrape_res = get_soup(clean_url)
        report = extract_full_website_report(clean_url, scrape_res)
        results.append(report)
    return results

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Website Safety & Intelligence Scraper")
    parser.add_argument("urls", nargs="*", default=["wikipedia.org"], help="Website URL(s) to analyze")
    parser.add_argument("-o", "--output", default="report.json", help="Output JSON file path")
    args = parser.parse_args()

    reports = run_scraper(args.urls)

    if not reports:
        print("\n[-] No reports generated.")
        return

    json_output = json.dumps(reports if len(reports) > 1 else reports[0], indent=2)
    
    print("\n" + "=" * 60)
    print("FINAL EXTRACTION REPORT:")
    print("=" * 60)
    print(json_output)

    # Automatically writes the file to your project directory
    file_path = args.output
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(json_output)
    
    print(f"\n[+] SUCCESS: JSON file created at '{file_path}'")
if __name__ == "__main__":
    main()
