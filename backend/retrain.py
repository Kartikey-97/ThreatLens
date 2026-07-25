import numpy as np
import joblib
from xgboost import XGBClassifier
import os

np.random.seed(42)

X = []
y = []

def gen_feature(is_phishing):
    if not is_phishing:
        domain_len = np.random.randint(5, 20)
        url_len = domain_len + np.random.randint(5, 30)
        
        # 30% brand (100), 70% unknown safe (0-65% similarity)
        if np.random.rand() < 0.3:
            sim_idx = 100.0
        else:
            sim_idx = np.random.uniform(0.0, 65.0)
            
        tld_prob = np.random.uniform(0.8, 1.0)
        subdomains = np.random.choice([0, 1], p=[0.5, 0.5])
        is_https = 1.0
        digits = 0
        special = 0
    else:
        # 40% typosquats, 60% random suspicious
        is_typosquat = np.random.choice([True, False], p=[0.4, 0.6])
        
        if is_typosquat:
            # Typosquats look VERY normal, except sim_idx is 75-99
            domain_len = np.random.randint(5, 20)
            url_len = domain_len + np.random.randint(5, 30)
            sim_idx = np.random.uniform(75.0, 99.0)
            tld_prob = np.random.uniform(0.8, 1.0)
            subdomains = 0
            is_https = 1.0
            digits = 0
            special = 0
        else:
            # Random suspicious
            domain_len = np.random.randint(15, 35)
            url_len = domain_len + np.random.randint(20, 80)
            sim_idx = np.random.uniform(0.0, 65.0)
            tld_prob = np.random.uniform(0.0, 0.5)
            subdomains = np.random.choice([2, 3, 4])
            is_https = np.random.choice([0.0, 1.0], p=[0.5, 0.5])
            digits = np.random.randint(5, 15)
            special = np.random.randint(5, 15)
            
    return [
        url_len, domain_len, sim_idx, np.random.uniform(0, 0.1),
        tld_prob, np.random.uniform(0.01, 0.08), 3.0, subdomains,
        url_len - digits - special, (url_len - digits - special)/url_len,
        digits, digits/url_len, 0, 0,
        special, special/url_len, is_https, digits/max(1, url_len - digits - special),
        special/url_len, 1.0 if domain_len > 25 else 0.0, 1.0 if tld_prob < 0.5 else 0.0
    ]

for _ in range(10000):
    X.append(gen_feature(is_phishing=False))
    y.append(0)
    
for _ in range(10000):
    X.append(gen_feature(is_phishing=True))
    y.append(1)

X = np.array(X, dtype=np.float64)
y = np.array(y, dtype=np.int32)

model = XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42)
model.fit(X, y)

models_dir = "/Users/kartikeygupta/Desktop/ThreatLens/models"
joblib.dump(model, os.path.join(models_dir, "url_model.pkl"))
