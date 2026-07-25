import urllib.parse
import Levenshtein
import math

URL_FEATURE_NAMES = [
    'URLLength', 'DomainLength', 'URLSimilarityIndex', 'CharContinuationRate',
    'TLDLegitimateProb', 'URLCharProb', 'TLDLength', 'NoOfSubDomain',
    'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL', 'IsHTTPS', 'digit_to_letter_ratio',
    'special_char_density', 'is_long_domain', 'low_tld_trust'
]

def extract_domain(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url if '//' in url else 'http://' + url)
        return parsed.hostname or ''
    except Exception:
        return ''

def extract_tld(url: str) -> str:
    try:
        domain = extract_domain(url)
        if not domain:
            return ''
        parts = domain.split('.')
        if len(parts) > 1:
            return parts[-1]
        return ''
    except Exception:
        return ''

def extract_url_features(url: str, brand_domains: list[dict]) -> list[float]:
    features = []
    
    # 1. URLLength
    try:
        url_length = float(len(url))
    except Exception:
        url_length = 0.0
    features.append(url_length)

    # 2. DomainLength
    try:
        domain = extract_domain(url)
        domain_length = float(len(domain))
    except Exception:
        domain_length = 0.0
    features.append(domain_length)

    # 3. URLSimilarityIndex
    try:
        max_sim = 0.0
        domain = extract_domain(url).lower()
        if domain:
            parts = domain.split('.')
            if len(parts) > 2 and parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu', 'ac'):
                base_domain = '.'.join(parts[-3:])
            elif len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
            else:
                base_domain = domain
                
            if brand_domains:
                for b in brand_domains:
                    brand = b.get('domain', '').lower()
                    if brand:
                        dist = Levenshtein.distance(base_domain, brand)
                        m_len = max(len(base_domain), len(brand))
                        sim = 1.0 - (dist / m_len) if m_len > 0 else 0.0
                        if sim > max_sim:
                            max_sim = sim
    except Exception:
        max_sim = 0.0
    features.append(float(max_sim) * 100.0)

    # 4. CharContinuationRate
    try:
        if len(url) < 2:
            ccr = 0.0
        else:
            pairs = 0
            for i in range(len(url) - 1):
                if url[i] == url[i+1]:
                    pairs += 1
            ccr = pairs / max(len(url) - 1, 1)
    except Exception:
        ccr = 0.0
    features.append(float(ccr))

    # 5. TLDLegitimateProb
    try:
        tld = extract_tld(url).lower()
        tld_probs = {
            'com': 0.95, 'org': 0.90, 'net': 0.85, 'edu': 0.99, 'gov': 0.99,
            'io': 0.80, 'co': 0.75, 'in': 0.80, 'tk': 0.05, 'ml': 0.05,
            'ga': 0.05, 'cf': 0.05, 'xyz': 0.15, 'top': 0.10, 'club': 0.20,
            'live': 0.20, 'icu': 0.10, 'space': 0.15, 'gq': 0.05
        }
        domain = extract_domain(url).lower()
        if domain.endswith('.co.in'):
            tld_legit_prob = 0.85
        else:
            tld_legit_prob = tld_probs.get(tld, 0.50)
    except Exception:
        tld_legit_prob = 0.50
    features.append(float(tld_legit_prob))

    # 6. URLCharProb
    try:
        if not url:
            url_char_prob = 0.0
        else:
            counts = {}
            for c in url:
                counts[c] = counts.get(c, 0) + 1
            log_sum = sum(math.log(count / len(url)) for count in counts.values())
            geo_mean = math.exp(log_sum / len(counts))
            url_char_prob = geo_mean
    except Exception:
        url_char_prob = 0.0
    features.append(float(url_char_prob))

    # 7. TLDLength
    try:
        tld = extract_tld(url)
        tld_length = len(tld)
    except Exception:
        tld_length = 0
    features.append(float(tld_length))

    # 8. NoOfSubDomain
    try:
        domain = extract_domain(url)
        parts = domain.split('.')
        no_of_subdomain = max(0, len(parts) - 2)
    except Exception:
        no_of_subdomain = 0
    features.append(float(no_of_subdomain))

    # 9. NoOfLettersInURL
    try:
        no_of_letters = sum(1 for c in url if c.isalpha())
    except Exception:
        no_of_letters = 0
    features.append(float(no_of_letters))

    # 10. LetterRatioInURL
    try:
        letter_ratio = no_of_letters / max(len(url), 1)
    except Exception:
        letter_ratio = 0.0
    features.append(float(letter_ratio))

    # 11. NoOfDegitsInURL
    try:
        no_of_digits = sum(1 for c in url if c.isdigit())
    except Exception:
        no_of_digits = 0
    features.append(float(no_of_digits))

    # 12. DegitRatioInURL
    try:
        digit_ratio = no_of_digits / max(len(url), 1)
    except Exception:
        digit_ratio = 0.0
    features.append(float(digit_ratio))

    # 13. NoOfEqualsInURL
    try:
        no_of_equals = url.count('=')
    except Exception:
        no_of_equals = 0
    features.append(float(no_of_equals))

    # 14. NoOfQMarkInURL
    try:
        no_of_qmark = url.count('?')
    except Exception:
        no_of_qmark = 0
    features.append(float(no_of_qmark))

    # 15. NoOfOtherSpecialCharsInURL
    try:
        std_chars = set('/:.-_?=&%#@')
        no_of_other_special = sum(1 for c in url if not c.isalnum() and c not in std_chars)
    except Exception:
        no_of_other_special = 0
    features.append(float(no_of_other_special))

    # 16. SpacialCharRatioInURL
    try:
        no_of_special = sum(1 for c in url if not c.isalnum())
        special_char_ratio = no_of_special / max(len(url), 1)
    except Exception:
        special_char_ratio = 0.0
    features.append(float(special_char_ratio))

    # 17. IsHTTPS
    try:
        is_https = 1.0 if url.lower().startswith('https://') else 0.0
    except Exception:
        is_https = 0.0
    features.append(is_https)

    # 18. digit_to_letter_ratio
    try:
        digit_to_letter_ratio = no_of_digits / max(no_of_letters, 1)
    except Exception:
        digit_to_letter_ratio = 0.0
    features.append(float(digit_to_letter_ratio))

    # 19. special_char_density
    try:
        special_char_density = special_char_ratio
    except Exception:
        special_char_density = 0.0
    features.append(float(special_char_density))

    # 20. is_long_domain
    try:
        is_long_domain = 1.0 if domain_length > 25 else 0.0
    except Exception:
        is_long_domain = 0.0
    features.append(is_long_domain)

    # 21. low_tld_trust
    try:
        low_tld_trust = 1.0 if tld_legit_prob < 0.5 else 0.0
    except Exception:
        low_tld_trust = 0.0
    features.append(low_tld_trust)

    return features
