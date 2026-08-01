from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import math
import re
from typing import Dict

from networksecurity.constant.training_pipeline import TARGET_COLUMN

from app.services.url_analysis import analyze_url


EXPECTED_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

# These are the numeric columns used to train the model currently stored in
# final_model/.  Keep this list in the same order as the training CSV schema.
MODEL_FEATURES = [
    "url_length", "domain_length", "url_entropy", "sub_domain",
    "digit_count", "special_char_count", "slash_count", "https_flag",
    "domain_entropy", "keyword_flag", "ip_flag", "hyphen_count",
    "query_length", "at_flag",
]

@dataclass(frozen=True)
class FeaturePayload:
    url: str
    features: Dict[str, float]


def extract_url_features(url: str) -> Dict[str, int]:
    return {name: int(value) for name, value in analyze_url(url).legacy_features.items()}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_model_features(url: str) -> Dict[str, float]:
    analysis = analyze_url(url)
    normalized = analysis.normalized_url
    hostname = analysis.hostname
    parsed_domain = hostname or analysis.domain
    tokens = set(analysis.suspicious_terms)
    return {
        "url_length": float(len(normalized)),
        "domain_length": float(len(parsed_domain)),
        "url_entropy": _entropy(normalized),
        "sub_domain": float(max(0, len(hostname.split(".")) - 2)),
        "digit_count": float(sum(character.isdigit() for character in normalized)),
        "special_char_count": float(sum(not character.isalnum() for character in normalized)),
        "slash_count": float(normalized.count("/")),
        "https_flag": float(normalized.lower().startswith("https://")),
        "domain_entropy": _entropy(parsed_domain),
        "keyword_flag": float(bool(tokens)),
        "ip_flag": float(bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname))),
        "hyphen_count": float(normalized.count("-")),
        "query_length": float(len(analysis.query)),
        "at_flag": float("@" in normalized),
    }


def normalize_feature_payload(url: str | None, features: Dict[str, float] | None) -> FeaturePayload:
    if features:
        normalized = {name: float(features.get(name, 0.0)) for name in MODEL_FEATURES}
        return FeaturePayload(url=url or "feature-input", features=normalized)

    if not url:
        raise ValueError("Either a raw URL or a feature map is required.")

    return FeaturePayload(url=url, features=extract_model_features(url))


def feature_frame_columns() -> list[str]:
    return MODEL_FEATURES.copy()
