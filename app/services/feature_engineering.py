from __future__ import annotations

from dataclasses import dataclass
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

@dataclass(frozen=True)
class FeaturePayload:
    url: str
    features: Dict[str, float]


def extract_url_features(url: str) -> Dict[str, int]:
    return {name: int(value) for name, value in analyze_url(url).legacy_features.items()}


def normalize_feature_payload(url: str | None, features: Dict[str, float] | None) -> FeaturePayload:
    if features:
        normalized = {name: float(features.get(name, 0.0)) for name in EXPECTED_FEATURES}
        return FeaturePayload(url=url or "feature-input", features=normalized)

    if not url:
        raise ValueError("Either a raw URL or a feature map is required.")

    derived = extract_url_features(url)
    return FeaturePayload(url=url, features={name: float(derived.get(name, 0.0)) for name in EXPECTED_FEATURES})


def feature_frame_columns() -> list[str]:
    return [column for column in EXPECTED_FEATURES if column != TARGET_COLUMN]
