import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import List, Optional
from backend.schemas import URLAnalysisResult

URL_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'icu', 'buzz', 'work', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq',
    'site', 'fun', 'click', 'link', 'rest', 'monster', 'beauty', 'surf', 'loan', 'gdn'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'tiny.cc', 'bl.ink', 'buff.ly'
}

SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'update', 'banking',
    'account', 'kyc', 'support', 'wallet', 'claim', 'reward', 'prize', 'gift',
    'bonus', 'free', 'dispatch', 'redelivery', 'parcel', 'crypto', 'bonus',
    'refund', 'authenticate', 're-verify', 'passcode', 'security-alert'
]

TARGETED_BRANDS = [
    'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay', 'amazon',
    'flipkart', 'netflix', 'paypal', 'apple', 'microsoft', 'google', 'fedex',
    'dhl', 'indiapost', 'ups', 'bluedart', 'incometax', 'whatsapp', 'telegram'
]

def extract_urls(text: str) -> List[str]:
    """Extract all URLs found within arbitrary text."""
    if not text:
        return []
    matches = URL_PATTERN.findall(text)
    cleaned = []
    for m in matches:
        # Strip trailing punctuation often caught by regex
        clean_url = m.rstrip('.,;:!?)>"\'')
        if clean_url not in cleaned:
            cleaned.append(clean_url)
    return cleaned

def calculate_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of string to detect random DGA domain generation."""
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probabilities)

def analyze_url(raw_url: str) -> URLAnalysisResult:
    """Performs deep technical feature inspection on a URL."""
    url = raw_url.strip()
    if not url:
        return URLAnalysisResult(
            url="",
            is_valid=False,
            domain="",
            tld="",
            is_ip_address=False,
            is_shortened=False,
            suspicious_tld=False,
            domain_entropy=0.0,
            uses_https=False,
            https_notice="No URL provided",
            suspicious_keywords=[],
            url_risk_score=0,
            flags=[]
        )

    # Normalize protocol if missing
    parsed_input = url
    if not re.match(r'^[a-zA-Z]+://', parsed_input):
        parsed_input = 'http://' + parsed_input

    try:
        parsed = urlparse(parsed_input)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        full_str = url.lower()
    except Exception:
        hostname = ""
        path = ""
        full_str = url.lower()

    flags = []
    risk_score = 0

    # 1. IP address in hostname
    is_ip = False
    try:
        if hostname:
            ipaddress.ip_address(hostname)
            is_ip = True
            risk_score += 40
            flags.append(f"Host uses raw numeric IP address ({hostname}) instead of a registered domain name (common evasion tactic).")
    except ValueError:
        is_ip = False

    # 2. Extract TLD
    domain_parts = hostname.split('.') if hostname else []
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    if is_suspicious_tld:
        risk_score += 25
        flags.append(f"Uses high-abuse, low-reputation top-level domain '.{tld}'.")

    # 3. URL Shortener check
    is_shortened = any(shortener in hostname for shortener in URL_SHORTENERS)
    if is_shortened:
        risk_score += 20
        flags.append(f"URL uses shortening service '{hostname}' which masks true landing page destination.")

    # 4. HTTPS analysis
    uses_https = url.lower().startswith('https://')
    if not uses_https:
        risk_score += 15
        https_notice = "Insecure HTTP protocol: Transport is not encrypted, credentials can be intercepted."
        flags.append(https_notice)
    else:
        https_notice = "HTTPS is present. IMPORTANT: HTTPS provides transport encryption but over 80% of modern phishing pages also use free SSL certificates (Let's Encrypt / Cloudflare). It does NOT confirm trust."

    # 5. Shannon Entropy of domain name
    domain_entropy = round(calculate_shannon_entropy(hostname), 2)
    if domain_entropy > 3.7 and len(hostname) > 12:
        risk_score += 15
        flags.append(f"High domain character randomness (Shannon entropy {domain_entropy} > 3.7), typical of algorithmically generated scam domains.")

    # 6. Excessive subdomains or unusual length
    if len(domain_parts) >= 4 and not is_ip:
        risk_score += 15
        flags.append(f"Excessive subdomain depth ({len(domain_parts)} levels) used to simulate authentic portal URLs.")

    if len(url) > 75:
        risk_score += 10
        flags.append(f"Abnormally long URL length ({len(url)} characters).")

    # 7. Credential symbol '@' in URL
    if '@' in url:
        risk_score += 35
        flags.append("URL contains '@' symbol; browsers treat preceding text as user info, redirecting to the host after the '@'.")

    # 8. Hyphens in domain
    if hostname.count('-') >= 2:
        risk_score += 15
        flags.append(f"Multiple hyphens in domain name ({hostname}) commonly used in typosquatting and fake bank brand imitations.")

    # 9. Suspicious keywords in URL
    matched_keywords = []
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in full_str:
            matched_keywords.append(kw)
    if matched_keywords:
        risk_score += min(len(matched_keywords) * 8, 25)
        flags.append(f"Contains security-sensitive tokens in URL: {', '.join(matched_keywords[:4])}")

    # 10. Brand Spoofing heuristic
    for brand in TARGETED_BRANDS:
        if brand in full_str:
            # Check if it's the actual legitimate primary domain or a spoof
            legit_domain = f"{brand}.com"
            legit_in = f"{brand}.co.in"
            if legit_domain not in hostname and legit_in not in hostname and f"{brand}.gov.in" not in hostname:
                risk_score += 30
                flags.append(f"Possible brand spoofing: URL mentions '{brand}' but domain is '{hostname}', not official '{brand}' domain.")
                break

    # Cap score at 100
    final_score = min(max(risk_score, 0), 100)

    return URLAnalysisResult(
        url=url,
        is_valid=bool(hostname),
        domain=hostname,
        tld=tld,
        is_ip_address=is_ip,
        is_shortened=is_shortened,
        suspicious_tld=is_suspicious_tld,
        domain_entropy=domain_entropy,
        uses_https=uses_https,
        https_notice=https_notice,
        suspicious_keywords=matched_keywords,
        url_risk_score=final_score,
        flags=flags
    )
