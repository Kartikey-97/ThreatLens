import requests
from bs4 import BeautifulSoup
from typing import Tuple, Dict, Any, Optional

def get_soup(url: str) -> Dict[str, Any]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)

        # DEBUG
        print("=" * 60)
        print("Status Code:", response.status_code)
        print("Final URL:", response.url)
        print("Content-Type:", response.headers.get("Content-Type"))
        print("Has <title>:", "<title>" in response.text.lower())
        print(response.text[:500])
        print("=" * 60)

        soup = BeautifulSoup(response.text, "html.parser")
        
        redirect_chain = [r.url for r in response.history] + [response.url]
        
        return {
            "success": True,
            "soup": soup,
            "html": response.text,
            "headers": dict(response.headers),
            "status_code": response.status_code,
            "final_url": response.url,
            "redirect_chain": redirect_chain,
            "error": None
        }
    except requests.exceptions.SSLError as e:
        return {
            "success": False,
            "soup": None,
            "html": "",
            "headers": {},
            "status_code": 0,
            "final_url": url,
            "redirect_chain": [],
            "error": f"SSL Error: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "soup": None,
            "html": "",
            "headers": {},
            "status_code": 0,
            "final_url": url,
            "redirect_chain": [],
            "error": str(e)
        }
    
get_soup("https://spotify.com")