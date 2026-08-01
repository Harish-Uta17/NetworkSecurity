from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Callable, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.model_service import model_service
from app.services.url_analysis import analyze_url


@dataclass(frozen=True)
class BenchmarkRow:
    name: str
    url: str
    label: int  # 0 = phishing, 1 = legitimate


BENCHMARK_ROWS: List[BenchmarkRow] = [
    BenchmarkRow("brand_path_mismatch", "http://www.dghjdgf.com/paypal.co.uk/cycgi-bin/webscrcmd=_home-customer&nav=1/loading.php", 0),
    BenchmarkRow("secure_account_login", "https://secure-account-verification.example.com/login", 0),
    BenchmarkRow("bank_confirm", "https://update-bank-security.example.net/confirm", 0),
    BenchmarkRow("office_alert", "https://office365-security-alert.example.org/reset", 0),
    BenchmarkRow("amazon_update", "https://amazon-order-confirm.example.click/session", 0),
    BenchmarkRow("random_domain_verify", "https://qzvptlmx.example.xyz/verify/account", 0),
    BenchmarkRow("paypal_help", "https://www.paypal.com/help", 1),
    BenchmarkRow("microsoft_download", "https://www.microsoft.com/en-us/download", 1),
    BenchmarkRow("google_news", "https://news.google.com/topstories", 1),
    BenchmarkRow("mozilla_docs", "https://developer.mozilla.org/en-US/docs", 1),
]


def legacy_heuristic_score(url: str) -> float:
    analysis = analyze_url(url)
    indicators = analysis.legacy_features
    score = 0.0

    if indicators.get("having_IP_Address", 1.0) < 0:
        score += 0.3
    if indicators.get("Shortining_Service", 1.0) < 0:
        score += 0.2
    if indicators.get("having_At_Symbol", 1.0) < 0:
        score += 0.15
    if indicators.get("double_slash_redirecting", 1.0) < 0:
        score += 0.15
    if indicators.get("Prefix_Suffix", 1.0) < 0:
        score += 0.15
    if indicators.get("SSLfinal_State", 1.0) < 0:
        score += 0.15
    if indicators.get("Abnormal_URL", 1.0) < 0:
        score += 0.1
    if indicators.get("port", 1.0) < 0:
        score += 0.1

    path_only = analysis.path.lower()
    lower_url = analysis.normalized_url.lower()
    suspicious_terms = ["cgi-bin", "webscr", "webscrcmd", "loading.php", "login", "verify", "update", "secure", "account", "signin"]
    for term in suspicious_terms:
        if term in path_only:
            score += 0.12
    if "/" in path_only and any(token in path_only for token in ["paypal", "paypal.co.uk", "paypalcom", "microsoft", "google", "apple", "bank", "secure"]):
        score += 0.12
    if lower_url.count("/") >= 3:
        score += 0.08

    return min(score, 1.0)


def legacy_predict(url: str, model, preprocessor, feature_names: List[str]) -> Tuple[int, float, str]:
    analysis = analyze_url(url)
    input_frame = pd.DataFrame([analysis.legacy_features], columns=feature_names)
    transformed = preprocessor.transform(input_frame)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(transformed)
        if probabilities.ndim == 1:
            probabilities = np.stack([1 - probabilities, probabilities], axis=1)
    else:
        probabilities = np.full((1, 2), 0.5)

    predicted_label = int(model.predict(transformed)[0])
    confidence = float(probabilities[0][predicted_label])
    heuristic_score = legacy_heuristic_score(url)
    if predicted_label == 1 and heuristic_score >= 0.45:
        predicted_label = 0
        confidence = max(confidence, heuristic_score)
    return predicted_label, confidence, f"heuristic={heuristic_score:.3f}"


def hybrid_predict(url: str) -> Tuple[int, float, str]:
    record = model_service.predict(url=url)
    predicted_label = 0 if record["prediction"] == "Phishing" else 1
    confidence = float(record["confidence_score"])
    return predicted_label, confidence, record.get("risk_score_breakdown", {}).get("text_ngram_risk", 0.0)


def main() -> None:
    snapshot = model_service._snapshot
    model = snapshot.model
    preprocessor = snapshot.preprocessor
    feature_names = snapshot.feature_names

    legacy_predictions: List[int] = []
    hybrid_predictions: List[int] = []
    labels: List[int] = []

    print("Benchmark rows:")
    for row in BENCHMARK_ROWS:
        legacy_label, legacy_conf, legacy_meta = legacy_predict(row.url, model, preprocessor, feature_names)
        hybrid_label, hybrid_conf, hybrid_meta = hybrid_predict(row.url)
        labels.append(row.label)
        legacy_predictions.append(legacy_label)
        hybrid_predictions.append(hybrid_label)
        print(
            f"- {row.name}: label={row.label} | legacy={legacy_label} conf={legacy_conf:.3f} {legacy_meta} | hybrid={hybrid_label} conf={hybrid_conf:.3f} ngram={hybrid_meta} | {row.url}"
        )

    print()
    print("Legacy metrics:")
    print(f"  accuracy={accuracy_score(labels, legacy_predictions):.3f}")
    print(f"  precision={precision_score(labels, legacy_predictions, zero_division=0):.3f}")
    print(f"  recall={recall_score(labels, legacy_predictions, zero_division=0):.3f}")
    print(f"  f1={f1_score(labels, legacy_predictions, zero_division=0):.3f}")
    print(f"  confusion={confusion_matrix(labels, legacy_predictions).tolist()}")

    print()
    print("Hybrid metrics:")
    print(f"  accuracy={accuracy_score(labels, hybrid_predictions):.3f}")
    print(f"  precision={precision_score(labels, hybrid_predictions, zero_division=0):.3f}")
    print(f"  recall={recall_score(labels, hybrid_predictions, zero_division=0):.3f}")
    print(f"  f1={f1_score(labels, hybrid_predictions, zero_division=0):.3f}")
    print(f"  confusion={confusion_matrix(labels, hybrid_predictions).tolist()}")


if __name__ == "__main__":
    main()
