from tranco import Tranco

# Cache the list locally to avoid downloading on every query
t = Tranco(cache=True, cache_dir='.tranco')

try:
    latest_list = t.list()
except Exception as e:
    print(f"[!] Warning: Could not initialize Tranco list: {e}")
    latest_list = None

def get_tranco_info(domain: str) -> dict:
    """
    Returns Tranco ranking details for a given root domain.
    """
    if not latest_list:
        return {
            "tranco_rank": None,
            "is_in_top_1m": False,
            "status": "Tranco database unavailable"
        }

    try:
        # Query domain rank (returns -1 if not listed in Top 1M)
        rank = latest_list.rank(domain)
        
        if rank != -1:
            return {
                "tranco_rank": rank,
                "is_in_top_1m": True,
                "status": "Found in Tranco Top 1M"
            }
        else:
            return {
                "tranco_rank": None,
                "is_in_top_1m": False,
                "status": "Not in Top 1M"
            }
    except Exception as e:
        return {
            "tranco_rank": None,
            "is_in_top_1m": False,
            "status": f"Error querying Tranco: {str(e)}"
        }