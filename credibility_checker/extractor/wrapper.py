from normalizer import extract_domain, normalize_URL
from extractor.company import extract_title, extract_company_name
from extractor.contacts import extract_emails, extract_social_links
from extractor.domain_info import get_ip_address, get_server_location, get_ssl_certificate_info, get_domain_creation_date
from extractor.tech_stack import detect_tech_stack
from extractor.safety import evaluate_website_safety
from extractor.metrics import extract_reviews_and_ratings, estimate_traffic_indicators
from extractor.scoring import calculate_composite_score

def extract_full_website_report(target_url: str, scrape_result: dict) -> dict:
    """
    Consolidates extraction across all 13 targeted fields and calculates an
    Overall Website Credibility Score (0-100) and Letter Grade (A+ to F).
    """
    clean_url = normalize_URL(target_url)
    hostname = extract_domain(clean_url)

    if not scrape_result.get("success"):
        # Network or SSL failure fallback report
        ssl_info = get_ssl_certificate_info(hostname)
        ip_addr = get_ip_address(hostname)
        server_loc = get_server_location(ip_addr) if ip_addr else {}
        domain_creation = get_domain_creation_date(hostname)

        partial_report = {
            "target_url": clean_url,
            "domain": hostname,
            "status": "Scrape Failed",
            "error": scrape_result.get("error"),
            "1_website_title": None,
            "2_company_name": None,
            "3_emails": [],
            "4_phone_numbers": [],
            "5_social_links": {},
            "6_domain_creation": domain_creation,
            "7_ssl_certificate": ssl_info,
            "8_ip_address": ip_addr,
            "9_server_location": server_loc,
            "10_technology_stack": {},
            "11_safety_and_reputation": {
                "safety_status": "UNSAFE" if "SSL Error" in str(scrape_result.get("error")) else "UNKNOWN",
                "risk_score": 100 if "SSL Error" in str(scrape_result.get("error")) else 50,
                "threat_flags": [f"Connection error: {scrape_result.get('error')}"]
            },
            "12_reviews_and_ratings": {},
            "13_traffic_estimates": {}
        }
        
        score_eval = calculate_composite_score(partial_report)
        partial_report["overall_credibility_score"] = score_eval
        return partial_report

    soup = scrape_result["soup"]
    html_text = scrape_result["html"]
    headers = scrape_result["headers"]

    # 1. Identity
    title = extract_title(soup)
    company_name = extract_company_name(soup)

    #bug check
    print("=" * 50)
    print("Extracted Title:", title)
    print("Extracted Company:", company_name)
    print("HTML Title:", soup.title)
    print("=" * 50)

    # 2. Contacts & Social
    emails = extract_emails(html_text)
    social_links = extract_social_links(soup, clean_url)

    # 3. Domain & Network Information
    ip_address = get_ip_address(hostname)
    server_location = get_server_location(ip_address)
    ssl_info = get_ssl_certificate_info(hostname)
    domain_creation = get_domain_creation_date(hostname)

    # 4. Tech Stack
    tech_stack = detect_tech_stack(headers, soup, html_text)

    # 5. Safety & Reputation
    safety_eval = evaluate_website_safety(clean_url, headers, soup, html_text, ssl_info)

    # 6. Reviews & Traffic
    reviews = extract_reviews_and_ratings(soup)
    traffic = estimate_traffic_indicators(hostname, headers, ssl_info)

    # Base payload
    report = {
        "target_url": clean_url,
        "domain": hostname,
        "status": "Success",
        "1_website_title": title,
        "2_company_name": company_name,
        "3_emails": emails,
        "4_social_links": social_links,
        "5_domain_creation": domain_creation,
        "6_ssl_certificate": ssl_info,
        "7_ip_address": ip_address,
        "8_server_location": server_location,
        "9_technology_stack": tech_stack,
        "10_safety_and_reputation": safety_eval,
        "11_reviews_and_ratings": reviews,
        "12_traffic_estimates": traffic
    }

    # Calculate Overall Score & Grade based on all 13 metrics
    score_eval = calculate_composite_score(report)
    report["overall_credibility_score"] = score_eval

    return report