from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
import math
import re
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
}

BRAND_TERMS = {
    "paypal",
    "amazon",
    "microsoft",
    "google",
    "bank",
    "apple",
    "office365",
    "outlook",
    "appleid",
    "chase",
    "wellsfargo",
    "netflix",
    "facebook",
    "instagram",
    "github",
    "adobe",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "account",
    "verify",
    "verification",
    "update",
    "secure",
    "security",
    "reset",
    "confirm",
    "billing",
    "payment",
    "support",
    "unlock",
    "recovery",
    "session",
    "webscr",
    "webscrcmd",
    "cgi-bin",
    "loading",
    "redirect",
    "auth",
}

SUSPICIOUS_EXTENSIONS = {
    ".php",
    ".cgi",
    ".asp",
    ".aspx",
    ".jsp",
    ".exe",
    ".scr",
    ".zip",
    ".rar",
    ".iso",
}

SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "xyz",
    "tk",
    "gq",
    "ml",
    "cf",
    "pw",
    "icu",
    "click",
    "work",
    "quest",
    "loan",
    "info",
    "biz",
    "ru",
    "cn",
}

FREE_HOSTING_DOMAINS = {
    "000webhostapp.com",
    "altervista.org",
    "blogspot.com",
    "firebaseapp.com",
    "github.io",
    "pages.dev",
    "site123.me",
    "weebly.com",
    "wixsite.com",
    "wordpress.com",
}

COMMON_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "co",
    "uk",
    "io",
    "ai",
    "app",
    "dev",
}

PHISHING_URL_CORPUS = [
    "https://secure-account-verification.example.com/login",
    "https://billing-update.example.net/confirm-payment",
    "https://office365-security-alert.example.org/reset",
    "https://cloud-storage-access.example.io/session-check",
    "https://paypal-security.example.com/login/verify",
    "https://microsoft-account.example.net/update/password",
    "https://google-docs-secure.example.org/account/verify",
    "https://banking-auth.example.co/reset/confirm",
    "http://www.paypal.com.verify-session.example.ru/login.php",
    "http://login-account-update.example.xyz/cgi-bin/webscr",
    "https://amazon-order-confirm.example.click/session",
    "https://appleid-verify.example.top/auth/update",
    "https://chase-security-alert.example.info/confirm",
    "https://secure-login.example.tk/account/recovery",
    "https://random-domain.example.cf/paypal.co.uk/loading.php",
]

BENIGN_URL_CORPUS = [
    "https://www.paypal.com/help",
    "https://www.microsoft.com/en-us/download",
    "https://news.google.com/topstories",
    "https://support.amazon.com/",
    "https://www.bankofamerica.com/",
    "https://www.apple.com/support/",
    "https://docs.python.org/3/",
    "https://developer.mozilla.org/en-US/",
    "https://www.github.com/explore",
    "https://www.netflix.com/browse",
]


@dataclass(frozen=True)
class URLAnalysis:
    url: str
    normalized_url: str
    hostname: str
    domain: str
    path: str
    query: str
    tld: str
    legacy_features: Dict[str, float]
    triggered_indicators: List[str]
    risk_breakdown: Dict[str, float]
    feature_contributions: List[Dict[str, float | str]]
    risk_score: float
    explanation: str
    suspicious_terms: List[str]
    brand_hits: List[str]


@dataclass(frozen=True)
class TextEvidence:
    score: float
    malicious_similarity: float
    benign_similarity: float
    top_ngrams: List[str]


def ensure_scheme(url: str) -> str:
    return url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else f"https://{url}"


def _tokenize(text: str) -> List[str]:
    return [token for token in re.split(r"[^a-z0-9]+", text.lower()) if token]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _count_encoded_chars(text: str) -> int:
    return len(re.findall(r"%[0-9a-fA-F]{2}", text))


def _has_double_slash_redirect(url: str) -> bool:
    stripped = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url, count=1)
    return "//" in stripped


def _subdomain_count(hostname: str) -> int:
    parts = [part for part in hostname.split(".") if part]
    return max(0, len(parts) - 2)


def _suspicious_path_tokens(path: str, query: str) -> List[str]:
    tokens = _tokenize(path) + _tokenize(query)
    return [token for token in tokens if token in SUSPICIOUS_KEYWORDS]


def _brand_hits(hostname: str, path: str, query: str) -> List[str]:
    path_tokens = _tokenize(path) + _tokenize(query)
    domain_tokens = _tokenize(hostname)
    hits = []
    for brand in BRAND_TERMS:
        if brand in path_tokens or brand in domain_tokens or brand in path.lower() or brand in query.lower():
            hits.append(brand)
    return sorted(set(hits))


def _domain_mismatch(hostname: str, path: str, query: str, brand_hits: List[str]) -> bool:
    if not brand_hits:
        return False
    domain_tokens = _tokenize(hostname)
    path_mentions_brand = any(brand in path.lower() or brand in query.lower() for brand in brand_hits)
    domain_is_brand = any(brand in domain_tokens for brand in brand_hits)
    embedded_domain = bool(re.search(r"/(?:[a-z0-9-]+\.)+(?:com|net|org|co\.uk|io|info|biz|gov|edu)(?:/|$)", f"{path}/{query}".lower()))
    return (path_mentions_brand and not domain_is_brand) or embedded_domain


def _hostname_reputation(hostname: str) -> float:
    if not hostname:
        return 0.0
    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else hostname.lower()
    if tld in SUSPICIOUS_TLDS:
        return 1.0
    if tld in COMMON_TLDS:
        return 0.18
    return 0.45


def _free_hosting_platform(hostname: str) -> bool:
    return any(hostname == domain or hostname.endswith(f".{domain}") or hostname.endswith(domain) for domain in FREE_HOSTING_DOMAINS)


def _complexity_score(url: str, path: str, query: str) -> float:
    length_score = min(len(url) / 140.0, 1.0)
    path_depth = min(len([segment for segment in path.split("/") if segment]), 6) / 6.0
    query_items = min(len(parse_qs(query)), 6) / 6.0 if query else 0.0
    special_chars = min(sum(url.count(char) for char in ["?", "&", "=", "%", "@", "-"]), 12) / 12.0
    return min(1.0, 0.32 * length_score + 0.24 * path_depth + 0.2 * query_items + 0.24 * special_chars)


def _character_distribution_score(url: str) -> float:
    if not url:
        return 0.0
    lower = url.lower()
    digits = sum(char.isdigit() for char in lower) / max(len(lower), 1)
    specials = sum(not char.isalnum() and char not in {":", "/", "."} for char in lower) / max(len(lower), 1)
    repeats = max((count for count in Counter(lower).values()), default=1) / max(len(lower), 1)
    return min(1.0, digits * 1.8 + specials * 3.0 + repeats * 4.0)


def _suspicious_extension(path: str) -> Tuple[bool, str | None]:
    lowered = path.lower()
    for extension in SUSPICIOUS_EXTENSIONS:
        if lowered.endswith(extension) or f"{extension}?" in lowered or f"{extension}/" in lowered:
            return True, extension
    return False, None


def _build_legacy_features(url: str, hostname: str, domain: str, path: str, query: str, tld: str, brand_hits: List[str], suspicious_tokens: List[str]) -> Dict[str, float]:
    url_length = len(url)
    subdomain_count = _subdomain_count(hostname)
    encoded_count = _count_encoded_chars(url)
    has_suspicious_extension, _ = _suspicious_extension(path)
    looks_like_random_domain = bool(re.match(r"^[a-z]{8,}$", hostname.replace(".", "")))

    return {
        "having_IP_Address": -1 if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname) else 1,
        "URL_Length": 1 if url_length < 54 else 0 if url_length < 75 else -1,
        "Shortining_Service": -1 if any(domain.endswith(shortener) for shortener in SHORTENER_DOMAINS) else 1,
        "having_At_Symbol": -1 if "@" in url else 1,
        "double_slash_redirecting": -1 if _has_double_slash_redirect(url) else 1,
        "Prefix_Suffix": -1 if "-" in hostname else 1,
        "having_Sub_Domain": -1 if subdomain_count >= 3 or (brand_hits and subdomain_count >= 1) else 0 if subdomain_count == 2 else 1,
        "SSLfinal_State": 1 if url.startswith("https://") else -1,
        "Domain_registeration_length": -1 if looks_like_random_domain or tld in SUSPICIOUS_TLDS else 1,
        "Favicon": 1,
        "port": -1 if re.search(r":(?!443|80)\d+$", domain) else 1,
        "HTTPS_token": -1 if "https" in hostname and not url.startswith("https://") else 1,
        "Request_URL": -1 if brand_hits and suspicious_tokens else 1,
        "URL_of_Anchor": -1 if suspicious_tokens else 0,
        "Links_in_tags": -1 if suspicious_tokens else 0,
        "SFH": -1 if suspicious_tokens or has_suspicious_extension else 0,
        "Submitting_to_email": -1 if "mailto:" in url.lower() else 1,
        "Abnormal_URL": -1 if "@" in domain or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname) or (brand_hits and _domain_mismatch(hostname, path, query, brand_hits)) else 1,
        "Redirect": -1 if _has_double_slash_redirect(url) or "redirect" in query.lower() else 0,
        "on_mouseover": 1,
        "RightClick": 1,
        "popUpWidnow": 1,
        "Iframe": 1,
        "age_of_domain": -1 if tld in SUSPICIOUS_TLDS else 0,
        "DNSRecord": 1,
        "web_traffic": 0,
        "Page_Rank": 0,
        "Google_Index": 1,
        "Links_pointing_to_page": -1 if suspicious_tokens else 0,
        "Statistical_report": -1 if encoded_count or suspicious_tokens else 0,
    }


def analyze_url(url: str) -> URLAnalysis:
    normalized_url = ensure_scheme(url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    domain = hostname or parsed.netloc.lower()
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""

    suspicious_tokens = _suspicious_path_tokens(path, query)
    brand_hits = _brand_hits(hostname, path, query)
    domain_mismatch = _domain_mismatch(hostname, path, query, brand_hits)
    encoded_count = _count_encoded_chars(normalized_url)
    subdomain_count = _subdomain_count(hostname)
    suspicious_extension, extension = _suspicious_extension(path)
    free_hosting_platform = _free_hosting_platform(hostname)
    entropy_score = min(1.0, max(0.0, (_entropy(normalized_url) - 3.5) / 2.4))
    complexity_score = _complexity_score(normalized_url, path, query)
    special_char_score = _character_distribution_score(normalized_url)
    tld_reputation_score = _hostname_reputation(hostname)
    redirect_score = 1.0 if _has_double_slash_redirect(normalized_url) or any(token in query.lower() for token in {"redirect", "return", "next", "url"}) else 0.0
    encoded_score = min(1.0, encoded_count / 3.0)
    keyword_score = min(1.0, len(suspicious_tokens) / 3.0)
    brand_score = 0.0
    if brand_hits:
        brand_score = 0.35
        if domain_mismatch:
            brand_score = 1.0
        elif any(brand in hostname for brand in brand_hits):
            brand_score = 0.7
    random_domain_score = 1.0 if re.match(r"^[a-z]{8,}$", hostname.replace(".", "")) else 0.0
    subdomain_score = min(1.0, max(0, subdomain_count - 1) / 4.0)
    extension_score = 1.0 if suspicious_extension else 0.0
    free_hosting_score = 1.0 if free_hosting_platform and (suspicious_extension or suspicious_tokens or domain_mismatch or subdomain_count >= 2) else 0.0

    risk_breakdown = {
        "brand_impersonation": round(brand_score, 3),
        "domain_path_mismatch": round(1.0 if domain_mismatch else 0.0, 3),
        "suspicious_keywords": round(keyword_score, 3),
        "suspicious_extension": round(extension_score, 3),
        "encoded_characters": round(encoded_score, 3),
        "entropy": round(entropy_score, 3),
        "character_distribution": round(special_char_score, 3),
        "url_complexity": round(complexity_score, 3),
        "tld_reputation": round(tld_reputation_score, 3),
        "subdomain_analysis": round(subdomain_score, 3),
        "redirect_pattern": round(redirect_score, 3),
        "random_domain": round(random_domain_score, 3),
        "free_hosting_platform": round(free_hosting_score, 3),
    }

    weights = {
        "brand_impersonation": 0.18,
        "domain_path_mismatch": 0.18,
        "suspicious_keywords": 0.14,
        "suspicious_extension": 0.12,
        "encoded_characters": 0.08,
        "entropy": 0.08,
        "character_distribution": 0.08,
        "url_complexity": 0.08,
        "tld_reputation": 0.05,
        "subdomain_analysis": 0.03,
        "redirect_pattern": 0.03,
        "random_domain": 0.03,
        "free_hosting_platform": 0.16,
    }
    risk_score = sum(risk_breakdown[name] * weights[name] for name in risk_breakdown)
    risk_score = min(1.0, round(float(risk_score), 4))

    triggered_indicators: List[str] = []
    if brand_score >= 0.35:
        if domain_mismatch:
            triggered_indicators.append("brand_name_present_in_path_not_domain")
        else:
            triggered_indicators.append("brand_impersonation")
    if suspicious_tokens:
        triggered_indicators.extend([f"keyword:{token}" for token in suspicious_tokens])
    if suspicious_extension and extension:
        triggered_indicators.append(f"suspicious_extension:{extension}")
    if encoded_count:
        triggered_indicators.append("encoded_characters_present")
    if subdomain_count >= 3:
        triggered_indicators.append("multiple_subdomains")
    if redirect_score:
        triggered_indicators.append("redirect_pattern")
    if entropy_score >= 0.55:
        triggered_indicators.append("high_entropy_url")
    if complexity_score >= 0.55:
        triggered_indicators.append("high_url_complexity")
    if special_char_score >= 0.55:
        triggered_indicators.append("unusual_character_distribution")
    if tld_reputation_score >= 0.75:
        triggered_indicators.append("suspicious_tld")
    if random_domain_score:
        triggered_indicators.append("random_domain_pattern")
    if free_hosting_score:
        triggered_indicators.append("free_hosting_platform")

    legacy_features = _build_legacy_features(normalized_url, hostname, domain, path, query, tld, brand_hits, suspicious_tokens)
    explanation_parts = []
    if domain_mismatch:
        explanation_parts.append("brand name is present in the path but not in the domain")
    if suspicious_tokens:
        explanation_parts.append(f"suspicious keywords found: {', '.join(sorted(set(suspicious_tokens)))}")
    if suspicious_extension and extension:
        explanation_parts.append(f"suspicious file endpoint detected: {extension}")
    if free_hosting_score:
        explanation_parts.append("hosted on a free web platform with other phishing indicators")
    if subdomain_count >= 3:
        explanation_parts.append("multiple subdomains detected")
    if encoded_count:
        explanation_parts.append("encoded characters present in the URL")
    if entropy_score >= 0.55:
        explanation_parts.append("high-entropy URL structure")
    if not explanation_parts and risk_score >= 0.55:
        explanation_parts.append("combined URL structure is inconsistent with a benign destination")
    if not explanation_parts:
        explanation_parts.append("no strong phishing indicators were triggered")

    feature_contributions = [
        {"feature": "brand_impersonation", "impact": round(brand_score, 3), "reason": "Brand token appears in the URL path or hostname"},
        {"feature": "domain_path_mismatch", "impact": round(1.0 if domain_mismatch else 0.0, 3), "reason": "Brand appears in the path but not in the registrable domain"},
        {"feature": "suspicious_keywords", "impact": round(keyword_score, 3), "reason": "Login, verification, account, or update terms detected"},
        {"feature": "suspicious_extension", "impact": round(extension_score, 3), "reason": "Suspicious script or payload-style extension present"},
        {"feature": "encoded_characters", "impact": round(encoded_score, 3), "reason": "Percent-encoded characters suggest obfuscation"},
        {"feature": "subdomain_analysis", "impact": round(subdomain_score, 3), "reason": "Multiple subdomains increase impersonation risk"},
        {"feature": "entropy", "impact": round(entropy_score, 3), "reason": "High entropy domains often indicate random generation"},
        {"feature": "tld_reputation", "impact": round(tld_reputation_score, 3), "reason": "TLD reputation is weaker than mainstream domains"},
        {"feature": "free_hosting_platform", "impact": round(free_hosting_score, 3), "reason": "Free hosting platforms are frequently used for phishing landing pages"},
    ]
    feature_contributions = sorted(feature_contributions, key=lambda item: float(item["impact"]), reverse=True)

    return URLAnalysis(
        url=url,
        normalized_url=normalized_url,
        hostname=hostname,
        domain=domain,
        path=path,
        query=query,
        tld=tld,
        legacy_features=legacy_features,
        triggered_indicators=sorted(set(triggered_indicators)),
        risk_breakdown=risk_breakdown,
        feature_contributions=feature_contributions,
        risk_score=risk_score,
        explanation="; ".join(explanation_parts),
        suspicious_terms=sorted(set(suspicious_tokens)),
        brand_hits=sorted(set(brand_hits)),
    )


class URLTextRiskModel:
    def __init__(self) -> None:
        corpus = PHISHING_URL_CORPUS + BENIGN_URL_CORPUS
        self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 6), lowercase=True, min_df=1)
        matrix = self.vectorizer.fit_transform(corpus)
        phishing_matrix = matrix[: len(PHISHING_URL_CORPUS)]
        benign_matrix = matrix[len(PHISHING_URL_CORPUS) :]
        self.malicious_centroid = np.asarray(phishing_matrix.mean(axis=0)).ravel()
        self.benign_centroid = np.asarray(benign_matrix.mean(axis=0)).ravel()

    def score(self, url: str) -> TextEvidence:
        normalized_url = ensure_scheme(url)
        vector = self.vectorizer.transform([normalized_url]).toarray().ravel()
        malicious_similarity = float(cosine_similarity([vector], [self.malicious_centroid])[0, 0])
        benign_similarity = float(cosine_similarity([vector], [self.benign_centroid])[0, 0])
        score = (malicious_similarity - benign_similarity + 1.0) / 2.0
        score = float(min(1.0, max(0.0, score)))

        feature_names = np.asarray(self.vectorizer.get_feature_names_out())
        ranked = np.argsort(vector)[::-1][:8]
        top_ngrams = [str(feature_names[index]) for index in ranked if vector[index] > 0]

        return TextEvidence(
            score=round(score, 4),
            malicious_similarity=round(malicious_similarity, 4),
            benign_similarity=round(benign_similarity, 4),
            top_ngrams=top_ngrams,
        )


@lru_cache(maxsize=1)
def get_url_text_risk_model() -> URLTextRiskModel:
    return URLTextRiskModel()
