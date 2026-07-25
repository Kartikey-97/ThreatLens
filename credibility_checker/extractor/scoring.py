import datetime
from typing import Dict, Any, List

def calculate_composite_score(extracted_data: Dict[str, Any]) -> Dict[str, Any]:
    points = {
        "security": 0,       # Max 30
        "identity": 0,       # Max 25
        "contacts": 0,       # Max 15
        "tech_infra": 0,     # Max 15
        "reputation": 0      # Max 15
    }
    
    positive_factors: List[str] = []
    penalties: List[str] = []

    # -------------------------------------------------------------
    # PILLAR 1: Security & Encryption (Max 30 Points)
    # -------------------------------------------------------------
    ssl_info = extracted_data.get("6_ssl_certificate", {})
    safety_eval = extracted_data.get("10_safety_and_reputation", {})
    url = extracted_data.get("target_url", "")

    if url.startswith("https://"):
        points["security"] += 10
        positive_factors.append("HTTPS Protocol enabled (+10)")
    else:
        penalties.append("Insecure HTTP Protocol (-10)")

    if ssl_info.get("has_ssl") and ssl_info.get("is_valid"):
        points["security"] += 10
        days_left = ssl_info.get("days_remaining", 0)

        if days_left > 365:
            positive_factors.append(
                f"Valid SSL Certificate issued by {ssl_info.get('issuer', 'Trusted CA')} ({days_left} days remaining) (+10)"
            )
        else:
            positive_factors.append(
                f"Valid SSL Certificate issued by {ssl_info.get('issuer', 'Trusted CA')} (+10)"
            )
    elif ssl_info.get("has_ssl"):
        penalties.append("SSL Certificate is expired or invalid (-15)")

    # Security Headers audit
    threat_flags = safety_eval.get("threat_flags", [])
    missing_headers_flag = [f for f in threat_flags if "Missing security headers" in f]
    if not missing_headers_flag and safety_eval.get("safety_status") == "SAFE":
        points["security"] += 10
        positive_factors.append("All standard HTTP Security Headers present (+10)")
    else:
        points["security"] += 5
        positive_factors.append("Partial HTTP Security Headers present (+5)")

    # -------------------------------------------------------------
    # PILLAR 2: Identity & Domain Age (Max 25 Points)
    # -------------------------------------------------------------
    domain_creation = extracted_data.get("5_domain_creation", {})
    creation_date_str = domain_creation.get("creation_date")

    if creation_date_str and creation_date_str != "Unknown / Redacted":
        try:
            created_dt = datetime.datetime.strptime(creation_date_str, "%Y-%m-%d")
            age_days = (datetime.datetime.now() - created_dt).days
            age_years = age_days // 365
            
            if age_years >= 5:
                points["identity"] += 15
                positive_factors.append(f"Established Domain Age ({age_years} years old) (+15)")
            elif age_years >= 1:
                points["identity"] += 10
                positive_factors.append(f"Domain registered for over 1 year ({age_years} yr) (+10)")
            elif age_days > 30:
                points["identity"] += 5
                positive_factors.append("Domain active for over 30 days (+5)")
            else:
                penalties.append("Brand new domain registered within the last 30 days (-10)")
        except Exception:
            points["identity"] += 5
    
    company_name = extracted_data.get("2_company_name")
    if company_name and len(company_name) > 2:
        points["identity"] += 5
        positive_factors.append(f"Verified Company Name: '{company_name}' (+5)")

    title = extracted_data.get("1_website_title")
    if title and len(title) > 3:
        points["identity"] += 5
        positive_factors.append("Valid Website Title tag present (+5)")

    # -------------------------------------------------------------
    # PILLAR 3: Contacts & Social Transparency (Max 15 Points)
    # -------------------------------------------------------------
    emails = extracted_data.get("3_emails", [])
    socials = extracted_data.get("4_social_links", {})

    if emails:
        points["contacts"] += 5
        positive_factors.append(
            f"Public Contact Email found ({emails[0]}) (+5)"
        )

    if socials:
        platform_count = len(socials)
        social_pts = min(platform_count * 5, 10)
        points["contacts"] += social_pts
        positive_factors.append(
            f"Linked Social Media Profiles ({', '.join(socials.keys())}) (+{social_pts})"
        )

    # -------------------------------------------------------------
    # PILLAR 4: Technology & Infrastructure (Max 15 Points)
    # -------------------------------------------------------------
    tech_stack = extracted_data.get("9_technology_stack", {})
    servers = tech_stack.get("web_server", [])
    frameworks = tech_stack.get("frameworks_and_libraries", [])
    cms = tech_stack.get("cms_and_ecommerce", [])
    ip_addr = extracted_data.get("7_ip_address")

    if servers:
        points["tech_infra"] += 4

    if frameworks:
        points["tech_infra"] += 3

    if cms:
        points["tech_infra"] += 3

    if ip_addr:
        points["tech_infra"] += 5


    # -------------------------------------------------------------
    # PILLAR 5: Reviews & Reputation (Max 15 Points)
    # -------------------------------------------------------------
    reviews = extracted_data.get("11_reviews_and_ratings", {})
    if reviews.get("rating_found"):
        points["reputation"] += 5
        positive_factors.append(f"Customer Rating Schema found ({reviews.get('rating_value')}/{reviews.get('best_rating')}) (+5)")
    
    traffic = extracted_data.get("12_traffic_estimates", {})

    tranco = traffic.get("tranco", {})
    tranco_rank = tranco.get("rank")
    # Tranco Popularity Score
    if isinstance(tranco_rank, int):

        if tranco_rank <= 100:
            points["reputation"] += 5
            positive_factors.append(
                f"Global Top 100 Website (Tranco Rank {tranco_rank}) (+5)"
            )

        elif tranco_rank <= 1000:
            points["reputation"] += 4
            positive_factors.append(
                f"Global Top 1,000 Website (Tranco Rank {tranco_rank}) (+4)"
            )

        elif tranco_rank <= 10000:
            points["reputation"] += 3
            positive_factors.append(
                f"Popular Website (Tranco Rank {tranco_rank}) (+3)"
            )

        elif tranco_rank <= 100000:
            points["reputation"] += 2
            positive_factors.append(
                f"Known Website (Tranco Rank {tranco_rank}) (+2)"
            )

        elif tranco_rank <= 500000:
            points["reputation"] += 1
            positive_factors.append(
                f"Indexed Website (Tranco Rank {tranco_rank}) (+1)"
            )

    safety_status = safety_eval.get("safety_status")
    if safety_status == "SAFE" and not threat_flags:
        points["reputation"] += 5
        positive_factors.append("Clean Safety Audit (No Threat Flags) (+5)")

    elif safety_status == "SAFE":
        points["reputation"] += 3
        positive_factors.append("Generally Safe Website (+3)")

    elif safety_status == "SUSPICIOUS":
        penalties.append("Suspicious Security Audit (-15)")
        
    elif safety_status == "UNSAFE":
        penalties.append("CRITICAL: Unsafe Security Audit (-30)")

    # Severe Red-Flag Deductions
    for flag in threat_flags:
        if "Password input field found on unencrypted" in flag:
            penalties.append("CRITICAL: Password form on unencrypted HTTP page (-40)")
        if "Obfuscated JavaScript" in flag:
            penalties.append("Obfuscated JavaScript code (-20)")
        if "Phishing keyword detected" in flag:
            penalties.append(f"Phishing Content Detected: {flag} (-25)")


    # Calculate Base Sum & Net Penalties
    points["reputation"] = min(points["reputation"], 15)
    raw_score = sum(points.values())
    
    # Calculate total penalty points
    total_penalty_deduction = 0
    for p in penalties:
        if "(-40)" in p: total_penalty_deduction += 40
        elif "(-30)" in p: total_penalty_deduction += 30
        elif "(-25)" in p: total_penalty_deduction += 25
        elif "(-20)" in p: total_penalty_deduction += 20
        elif "(-15)" in p: total_penalty_deduction += 15
        elif "(-10)" in p: total_penalty_deduction += 10

    final_score = min(max(raw_score - total_penalty_deduction, 0), 100)

    # Assign Letter Grade
    if final_score >= 90:
        grade = "A+"
        confidence = "Excellent Trust & High Credibility"
    elif final_score >= 80:
        grade = "A"
        confidence = "Good Trust & Low Risk"
    elif final_score >= 70:
        grade = "B"
        confidence = "Moderate Trust"
    elif final_score >= 60:
        grade = "C"
        confidence = "Fair / Use Caution"
    elif final_score >= 50:
        grade = "D"
        confidence = "Low Trust / Suspicious"
    else:
        grade = "F"
        confidence = "High Risk / Highly Suspicious or Unsafe"

    return {
        "overall_score": final_score,
        "grade": grade,
        "trust_classification": confidence,
        "score_breakdown": {
            "security": f"{points['security']}/30",
            "identity_and_domain": f"{points['identity']}/25",
            "contacts_and_transparency": f"{points['contacts']}/15",
            "tech_and_infrastructure": f"{points['tech_infra']}/15",
            "reputation_and_reviews": f"{points['reputation']}/15"
        },
        "positive_trust_signals": positive_factors,
        "penalty_risk_signals": penalties
    }
