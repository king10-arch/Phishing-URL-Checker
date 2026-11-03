from difflib import SequenceMatcher


url = input("Enter a website url:")
risk_score = 0
reasons = []


def check_https(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 3
        reasons.append("The website does not use HTTPS.")

    return score, reasons

   
def check_login(url):
    score = 0
    reasons = []
    if "login" in url:
        score += 3
        reasons.append("The website contains 'login' in the URL, which may indicate a login page and potential phishing risk.")

    return score, reasons

def check_verify(url):
    score = 0
    reasons = []
    if "verify" in url:
        score += 3
        reasons.append("The website contains 'verify' in the URL, which may indicate a verification page and potential phishing risk.")

    return score, reasons

def check_secure(url):
    score = 0
    reasons = []
    if "secure" in url:
        score += 3
        reasons.append("The website contains 'secure' in the URL, which may indicate a secure page and potential phishing risk.")

    return score, reasons

def check_account(url):
    score = 0
    reasons = []
    if "account" in url:
        score += 3
        reasons.append("The website contains 'account' in the URL, which may indicate an account page and potential phishing risk.")

    return score, reasons

def check_update(url):
    score = 0
    reasons = []
    if "update" in url:
        score += 3
        reasons.append("The website contains 'update' in the URL, which may indicate an update page and potential phishing risk.")

    return score, reasons

def check_char(url):
    score = 0
    reasons = []
    if any(char in url for char in ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']):
        score += 2
        reasons.append("The website URL contains special characters, which may indicate a suspicious or phishing site.")

    return score, reasons
def check_length(url):
    score = 0
    reasons = []
    if len(url) > 60:
        score += 2
        reasons.append("The website URL is longer than 60 characters, which may indicate a suspicious or phishing site.")

    return score, reasons

from urllib.parse import urlparse
from difflib import SequenceMatcher

def check_lookalike(url):
    score = 0
    reasons = []

    brands = [
        "paypal",
        "google",
        "amazon",
        "microsoft",
        "facebook",
        "apple"
    ]

    parsed = urlparse(url if "://" in url else "//" + url)

    host = parsed.hostname or ""

    if host.startswith("www."):
        host = host[4:]

    parts = host.split(".")
    name = parts[-2] if len(parts) >= 2 else parts[0]

    for piece in name.split("-"):
        for brand in brands:
            similarity = SequenceMatcher(None, piece, brand).ratio()

            if similarity > 0.8 and piece != brand:
                score += 5
                reasons.append(
                    f"The domain '{host}' looks similar to '{brand}', which may indicate a phishing attempt."
                )

    return score, reasons

checks = [
    check_https,
    check_login,
    check_verify,
    check_secure,
    check_account,
    check_update,
    check_char,
    check_length,
    check_lookalike
]

for check in checks:
    score, found_reasons = check(url)
    risk_score += score
    reasons.extend(found_reasons)


print(f"Risk Score: {risk_score}")
print(f"Reasons for the risk score:{reasons}")
