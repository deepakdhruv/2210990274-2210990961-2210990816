
# Study of Machine Learning and Rule-Based Phishing Detection
# Simple Hybrid Phishing Detection System
# Authors:
# Vinayak Sharma
# Dhruv Grover
# Shaurya Gupta

import re
from urllib.parse import urlparse

# -----------------------------
# Rule-Based Detection Section
# -----------------------------

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "bank",
    "update",
    "account",
    "paypal",
    "signin"
]

def rule_based_detection(url):
    score = 0

    # Rule 1: URL length
    if len(url) > 75:
        score += 1

    # Rule 2: Presence of IP address
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    if re.search(ip_pattern, url):
        score += 1

    # Rule 3: Presence of '@'
    if "@" in url:
        score += 1

    # Rule 4: Too many subdomains
    domain = urlparse(url).netloc
    if domain.count(".") > 3:
        score += 1

    # Rule 5: Suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 1
            break

    return score


# -----------------------------------
# Simulated ML Classification Section
# -----------------------------------

def ml_prediction(rule_score):
    '''
    Simulated ML model prediction
    '''
    if rule_score >= 4:
        probability = 0.95
    elif rule_score == 3:
        probability = 0.80
    elif rule_score == 2:
        probability = 0.55
    else:
        probability = 0.10

    return probability


# -----------------------------------
# Hybrid Detection Framework
# -----------------------------------

def hybrid_detection(url):
    rule_score = rule_based_detection(url)
    probability = ml_prediction(rule_score)

    print("\nURL:", url)
    print("Rule-Based Score:", rule_score)
    print("ML Probability:", round(probability, 2))

    if probability >= 0.80:
        print("Result: PHISHING WEBSITE DETECTED")
    elif probability <= 0.30:
        print("Result: SAFE WEBSITE")
    else:
        print("Result: SUSPICIOUS - Needs Manual Review")


# -----------------------------------
# Main Program
# -----------------------------------

if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify",
        "https://paypal-secure-login-update.com",
        "https://github.com",
        "http://bank-account-verify-security-alert.com"
    ]

    print("Hybrid Phishing Detection System")
    print("-" * 40)

    for url in test_urls:
        hybrid_detection(url)
