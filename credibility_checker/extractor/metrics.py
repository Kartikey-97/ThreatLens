import csv
import os
import json
from typing import Dict, Any, Optional

def extract_reviews_and_ratings(soup) -> Dict[str, Any]:
    if not soup:
        return {"rating_value": None, "review_count": 0, "best_rating": 5, "rating_found": False}

    scripts = soup.find_all("script", type="application/ld+json")
    for script in scripts:
        if not script.string:
            continue
        try:
            data = json.loads(script.string)
            items = data if isinstance(data, list) else [data]
            
            for item in items:
                if isinstance(item, dict):
                    # Check direct aggregateRating
                    rating_data = item.get("aggregateRating") or item.get("rating")
                    
                    if not rating_data and item.get("@type") == "AggregateRating":
                        rating_data = item
                        
                    if rating_data and isinstance(rating_data, dict):
                        rating_val = rating_data.get("ratingValue")
                        review_cnt = rating_data.get("reviewCount") or rating_data.get("ratingCount") or 0
                        best_val = rating_data.get("bestRating") or 5
                        
                        if rating_val is not None:
                            return {
                                "rating_value": str(rating_val),
                                "review_count": int(review_cnt),
                                "best_rating": str(best_val),
                                "rating_found": True
                            }
        except (json.JSONDecodeError, TypeError):
            continue

    return {
        "rating_value": "N/A",
        "review_count": 0,
        "best_rating": "5",
        "rating_found": False
    }



TRANCO_CACHE = None


def get_tranco_rank(domain: str) -> Optional[int]:
    """
    Returns the Tranco rank of a domain.
    """

    global TRANCO_CACHE

    if TRANCO_CACHE is None:
        TRANCO_CACHE = {}

        csv_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "tranco.csv"
        )

        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)

                for row in reader:
                    if len(row) < 2:
                        continue

                    try:
                        rank = int(row[0])
                    except ValueError:
                        continue  # Skip header row

                    site = row[1].lower().strip()

                    if site.startswith("www."):
                        site = site[4:]

                    TRANCO_CACHE[site] = rank

        except FileNotFoundError:
            return None

    domain = domain.lower().strip()

    if domain.startswith("www."):
        domain = domain[4:]

    return TRANCO_CACHE.get(domain)




def estimate_traffic_indicators(
    domain: str,
    headers: Dict[str, str],
    ssl_info: Dict[str, Any]
) -> Dict[str, Any]:

    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    server = headers_lower.get("server", "")

    has_global_cdn = any(
        cdn in server
        for cdn in [
            "cloudflare",
            "cloudfront",
            "akamai",
            "fastly"
        ]
    )

    tranco_rank = get_tranco_rank(domain)

    if tranco_rank:
        if tranco_rank <= 100:
            traffic_tier = "Top 100 Websites"
        elif tranco_rank <= 1000:
            traffic_tier = "Extremely High Traffic"
        elif tranco_rank <= 10000:
            traffic_tier = "Very High Traffic"
        elif tranco_rank <= 100000:
            traffic_tier = "High Traffic"
        elif tranco_rank <= 500000:
            traffic_tier = "Moderate Traffic"
        else:
            traffic_tier = "Low Traffic"

    elif has_global_cdn:
        traffic_tier = "Enterprise CDN"

    elif ssl_info.get("has_ssl"):
        traffic_tier = "Moderate Web Presence"

    else:
        traffic_tier = "Low Web Presence"

    return {
        "estimated_traffic_tier": traffic_tier,
        "uses_global_cdn": has_global_cdn,
        "tranco": {
            "rank": tranco_rank,
            "available": tranco_rank is not None
        }
    }