import re
import scipy.sparse

EMAIL_FEATURE_NAMES = [
    'text_length', 'word_count', 'num_links', 'num_exclaim', 'num_dollar',
    'has_urgent_words', 'has_money_words', 'num_uppercase_words', 'uppercase_ratio', 'num_digits'
]

def compute_engineered_features(text: str) -> list[float]:
    features = []
    
    # 1. text_length
    try:
        text_length = float(len(text))
    except Exception:
        text_length = 0.0
    features.append(text_length)

    # 2. word_count
    try:
        words = text.split()
        word_count = float(len(words))
    except Exception:
        word_count = 0.0
        words = []
    features.append(word_count)

    # 3. num_links
    try:
        num_links = float(text.count('http://') + text.count('https://') + text.count('www.'))
    except Exception:
        num_links = 0.0
    features.append(num_links)

    # 4. num_exclaim
    try:
        num_exclaim = float(text.count('!'))
    except Exception:
        num_exclaim = 0.0
    features.append(num_exclaim)

    # 5. num_dollar
    try:
        num_dollar = float(text.count('$'))
    except Exception:
        num_dollar = 0.0
    features.append(num_dollar)

    # 6. has_urgent_words
    try:
        urgent_pattern = re.compile(r'\b(urgent|verify|suspend|immediately|act now|click here|limited time|expire)\b', re.IGNORECASE)
        has_urgent_words = 1.0 if urgent_pattern.search(text) else 0.0
    except Exception:
        has_urgent_words = 0.0
    features.append(has_urgent_words)

    # 7. has_money_words
    try:
        money_pattern = re.compile(r'\b(bank|account|password|ssn|credit card|paypal|wire transfer|winner|prize|inheritance)\b', re.IGNORECASE)
        has_money_words = 1.0 if money_pattern.search(text) else 0.0
    except Exception:
        has_money_words = 0.0
    features.append(has_money_words)

    # 8. num_uppercase_words
    try:
        num_uppercase_words = float(sum(1 for w in words if w.isupper() and len(w) >= 2))
    except Exception:
        num_uppercase_words = 0.0
    features.append(num_uppercase_words)

    # 9. uppercase_ratio
    try:
        uppercase_ratio = num_uppercase_words / max(word_count, 1.0)
    except Exception:
        uppercase_ratio = 0.0
    features.append(float(uppercase_ratio))

    # 10. num_digits
    try:
        num_digits = float(sum(1 for c in text if c.isdigit()))
    except Exception:
        num_digits = 0.0
    features.append(num_digits)

    return features

def extract_email_features(text: str, tfidf_vectorizer) -> scipy.sparse.csr_matrix:
    try:
        tfidf_matrix = tfidf_vectorizer.transform([text])
    except Exception:
        return scipy.sparse.csr_matrix((1, 10))

    try:
        engineered = compute_engineered_features(text)
        engineered_sparse = scipy.sparse.csr_matrix([engineered])
    except Exception:
        engineered_sparse = scipy.sparse.csr_matrix((1, 10))

    try:
        combined = scipy.sparse.hstack([tfidf_matrix, engineered_sparse])
        return combined
    except Exception:
        return scipy.sparse.csr_matrix((1, 10))
