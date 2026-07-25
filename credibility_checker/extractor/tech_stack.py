from typing import Dict, List, Any

def detect_tech_stack(headers: Dict[str, str], soup, html_text: str) -> Dict[str, Any]:
    """
    Detects server software, CMS, frontend frameworks, UI libraries, and analytics tools
    from HTTP response headers and HTML source signatures.
    """
    detected_tech = {
        "web_server": [],
        "frameworks_and_libraries": [],
        "cms_and_ecommerce": [],
        "analytics_and_scripts": []
    }

    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    html_lower = html_text.lower() if html_text else ""

    # 1. Server Software & CDN Detection
    server_header = headers_lower.get("server", "")
    if "nginx" in server_header:
        detected_tech["web_server"].append("Nginx")
    if "apache" in server_header:
        detected_tech["web_server"].append("Apache")
    if "cloudflare" in server_header or "cf-ray" in headers_lower:
        detected_tech["web_server"].append("Cloudflare CDN")
    if "caddy" in server_header:
        detected_tech["web_server"].append("Caddy Server")
    if "litespeed" in server_header:
        detected_tech["web_server"].append("LiteSpeed")

    x_powered = headers_lower.get("x-powered-by", "")
    if "php" in x_powered or ".php" in html_lower:
        detected_tech["frameworks_and_libraries"].append("PHP")
    if "asp.net" in x_powered:
        detected_tech["frameworks_and_libraries"].append("ASP.NET")

    # 2. CMS & E-commerce Detection
    if "wp-content" in html_lower or "wp-includes" in html_lower:
        detected_tech["cms_and_ecommerce"].append("WordPress")
    if "shopify" in html_lower or "cdn.shopify.com" in html_lower:
        detected_tech["cms_and_ecommerce"].append("Shopify")
    if "woocommerce" in html_lower:
        detected_tech["cms_and_ecommerce"].append("WooCommerce")
    if "wix.com" in html_lower or "wix-code" in html_lower:
        detected_tech["cms_and_ecommerce"].append("Wix")
    if "squarespace" in html_lower:
        detected_tech["cms_and_ecommerce"].append("Squarespace")
    if "webflow" in html_lower:
        detected_tech["cms_and_ecommerce"].append("Webflow")
    if "drupal" in html_lower:
        detected_tech["cms_and_ecommerce"].append("Drupal")
    if "joomla" in html_lower:
        detected_tech["cms_and_ecommerce"].append("Joomla")

    # 3. JavaScript Frameworks & UI Libraries
    if "__next" in html_lower or "_next/static" in html_lower:
        detected_tech["frameworks_and_libraries"].append("Next.js")
    if "react" in html_lower or "react-root" in html_lower or "data-reactroot" in html_lower:
        detected_tech["frameworks_and_libraries"].append("React")
    if "vue" in html_lower or "v-data-" in html_lower:
        detected_tech["frameworks_and_libraries"].append("Vue.js")
    if "ng-app" in html_lower or "angular" in html_lower:
        detected_tech["frameworks_and_libraries"].append("Angular")
    if "jquery" in html_lower:
        detected_tech["frameworks_and_libraries"].append("jQuery")
    if "bootstrap" in html_lower:
        detected_tech["frameworks_and_libraries"].append("Bootstrap")
    if "tailwind" in html_lower:
        detected_tech["frameworks_and_libraries"].append("Tailwind CSS")

    # 4. Analytics & Marketing Scripts
    if "google-analytics.com" in html_lower or "googletagmanager.com" in html_lower or "gtag" in html_lower:
        detected_tech["analytics_and_scripts"].append("Google Analytics / GTM")
    if "connect.facebook.net" in html_lower or "fbevents.js" in html_lower:
        detected_tech["analytics_and_scripts"].append("Meta Pixel (Facebook)")
    if "hotjar.com" in html_lower:
        detected_tech["analytics_and_scripts"].append("Hotjar")

    # Deduplicate entries
    for key in detected_tech:
        detected_tech[key] = list(set(detected_tech[key]))

    return detected_tech
