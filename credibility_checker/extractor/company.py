import json
from typing import Optional, Dict, Any

def extract_title(soup) -> Optional[str]:
    if not soup:
        return None

    og_title = soup.find("meta", attrs={"property": "og:title"})
    if og_title and og_title.get("content"):
        return og_title.get("content").strip()

    if soup.title and soup.title.string:
        return soup.title.string.strip()

    return None


def extract_company_name(soup) -> Optional[str]:
    if not soup:
        return None

    # 1. Check JSON-LD schema
    scripts = soup.find_all("script", type="application/ld+json")
    for script in scripts:
        if not script.string:
            continue
        try:
            data = json.loads(script.string)
            items = data if isinstance(data, list) else [data]
            
            for item in items:
                if isinstance(item, dict):
                    # Check direct type
                    item_type = item.get("@type")
                    if item_type in ["Organization", "Corporation", "LocalBusiness", "Brand"]:
                        if item.get("name"):
                            return str(item.get("name")).strip()
                    
                    # Check graph array inside json-ld
                    if "@graph" in item and isinstance(item["@graph"], list):
                        for sub_item in item["@graph"]:
                            if isinstance(sub_item, dict) and sub_item.get("@type") in ["Organization", "Corporation", "LocalBusiness", "Brand"]:
                                if sub_item.get("name"):
                                    return str(sub_item.get("name")).strip()
        except (json.JSONDecodeError, TypeError):
            continue

    # 2. Check OpenGraph site_name
    og_site_name = soup.find("meta", attrs={"property": "og:site_name"})
    if og_site_name and og_site_name.get("content"):
        return og_site_name.get("content").strip()

    # 3. Check Meta Author or Copyright
    meta_author = soup.find("meta", attrs={"name": "author"})
    if meta_author and meta_author.get("content"):
        return meta_author.get("content").strip()

    # 4. Fallback to title heuristic (e.g. "Products | Acme Corp" -> "Acme Corp")
    title = extract_title(soup)
    if title:
        separators = ["|", "-", "–", "—", "::"]
        for sep in separators:
            if sep in title:
                parts = title.split(sep)    
                parts = [p.strip() for p in parts]

                # Return the shortest part.
                return min(parts, key=len)
        return title.strip()
    return None
