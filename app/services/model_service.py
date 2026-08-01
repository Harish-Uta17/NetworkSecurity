from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from app.core.config import get_settings
from app.core.logging import configure_app_logging
from app.services.feature_engineering import feature_frame_columns, normalize_feature_payload
from app.services.threat_scoring import threat_profile
from app.services.url_analysis import analyze_url, get_url_text_risk_model
from networksecurity.utils.main_utils.utils import load_numpy_array_data, load_object


logger = configure_app_logging()

DECISION_THRESHOLD = 0.52
HIGH_RISK_THRESHOLD = 0.75
CRITICAL_RISK_THRESHOLD = 0.9


@dataclass
class ModelSnapshot:
    model: object | None
    preprocessor: object | None
    metrics: Dict[str, float]
    latest_artifact_dir: str | None
    feature_names: List[str]
    load_error: str | None = None


class ModelService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._snapshot = self._load_snapshot()

    def _latest_artifact_dir(self) -> Path | None:
        if not self.settings.artifacts_dir.exists():
            return None
        runs = [path for path in self.settings.artifacts_dir.iterdir() if path.is_dir()]
        return sorted(runs)[-1] if runs else None

    def _load_snapshot(self) -> ModelSnapshot:
        model = None
        preprocessor = None
        metrics: Dict[str, float] = {}
        feature_names = feature_frame_columns()
        latest_artifact_dir = self._latest_artifact_dir()
        load_error: str | None = None

        try:
            missing = [
                str(path)
                for path in (self.settings.model_path, self.settings.preprocessor_path)
                if not path.is_file()
            ]
            if missing:
                load_error = "Missing model artifact file(s): " + ", ".join(missing)
            else:
                preprocessor = load_object(str(self.settings.preprocessor_path))
                model = load_object(str(self.settings.model_path))
                estimator = getattr(model, "model", model)
                if hasattr(estimator, "n_jobs"):
                    estimator.n_jobs = 1
        except Exception as exc:
            load_error = f"{type(exc).__name__}: {exc}"
            logger.exception(
                "Failed to load model artifacts from %s. Check that files are deployed "
                "and dependency versions match.",
                self.settings.model_dir,
            )

        # The serialized preprocessor is the source of truth for the model's
        # input schema. This also keeps metrics compatible with older builds
        # that still exposed the legacy 30-feature dashboard schema.
        fitted_feature_names = getattr(preprocessor, "feature_names_in_", None)
        if fitted_feature_names is not None:
            fitted_feature_names = [str(name) for name in fitted_feature_names]
            feature_names = fitted_feature_names

        if latest_artifact_dir:
            test_path = latest_artifact_dir / "data_transformation" / "transformed" / "test.npy"
            if test_path.exists() and model is not None and preprocessor is not None:
                try:
                    test_arr = load_numpy_array_data(str(test_path))
                    x_test, y_test = test_arr[:, :-1], test_arr[:, -1]
                    # Computing metrics over the entire test set at every app
                    # startup is expensive on Streamlit Cloud. A deterministic
                    # sample is sufficient for the dashboard health metrics.
                    max_metric_rows = int(os.getenv("MODEL_METRICS_MAX_ROWS", "5000"))
                    if max_metric_rows > 0 and len(x_test) > max_metric_rows:
                        sample_indices = np.linspace(0, len(x_test) - 1, max_metric_rows, dtype=int)
                        x_test, y_test = x_test[sample_indices], y_test[sample_indices]
                    x_test_df = pd.DataFrame(x_test, columns=feature_names)
                    x_transformed = preprocessor.transform(x_test_df)
                    predictions = model.predict(x_transformed)
                    metrics = {
                        "accuracy": float(accuracy_score(y_test, predictions)),
                        "precision": float(precision_score(y_test, predictions, zero_division=0)),
                        "recall": float(recall_score(y_test, predictions, zero_division=0)),
                        "f1_score": float(f1_score(y_test, predictions, zero_division=0)),
                    }
                    try:
                        if hasattr(model, "predict_proba"):
                            probabilities = model.predict_proba(x_transformed)
                            metrics["roc_auc"] = float(roc_auc_score(y_test, probabilities[:, 1]))
                    except Exception:
                        pass
                    tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
                    metrics.update(
                        {
                            "true_negative": float(tn),
                            "false_positive": float(fp),
                            "false_negative": float(fn),
                            "true_positive": float(tp),
                        }
                    )
                except Exception as exc:
                    logger.warning("Failed to compute model metrics: %s", exc)

        # Artifacts/ is intentionally excluded from deployment. Use the
        # metrics saved beside the model when the test set is unavailable.
        if not metrics:
            metrics_path = self.settings.model_dir / "metrics.json"
            if metrics_path.is_file():
                try:
                    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    logger.warning("Failed to load deployment metrics: %s", exc)

        return ModelSnapshot(
            model=model,
            preprocessor=preprocessor,
            metrics=metrics,
            latest_artifact_dir=str(latest_artifact_dir) if latest_artifact_dir else None,
            feature_names=feature_names,
            load_error=load_error,
        )

    @property
    def is_ready(self) -> bool:
        return self._snapshot.model is not None and self._snapshot.preprocessor is not None

    def _tabular_probability(self, transformed_frame) -> float:
        estimator = self._snapshot.model
        if estimator is None:
            return 0.5
        if hasattr(estimator, "predict_proba"):
            probabilities = estimator.predict_proba(transformed_frame)
            if probabilities.ndim == 1:
                probabilities = np.stack([1 - probabilities, probabilities], axis=1)
            return float(probabilities[0][0])
        if hasattr(estimator, "decision_function"):
            scores = np.asarray(estimator.decision_function(transformed_frame))
            if scores.ndim > 1:
                scores = scores.ravel()
            return float(1 / (1 + np.exp(scores[0])))
        return 0.5

    def _combine_scores(self, tabular_phish_prob: float, analysis_risk: float, text_risk: float) -> float:
        combined = max(analysis_risk, text_risk, tabular_phish_prob * 0.85)
        if analysis_risk >= 0.8 or text_risk >= 0.8:
            combined = max(combined, 0.9)
        if analysis_risk >= 0.55 and (analysis_risk >= text_risk or tabular_phish_prob >= 0.45):
            combined = max(combined, 0.58)
        return float(min(1.0, max(0.0, combined)))

    def _classify_from_score(self, risk_score: float) -> tuple[int, str]:
        if risk_score >= DECISION_THRESHOLD:
            return 0, "High" if risk_score >= HIGH_RISK_THRESHOLD else "Moderate"
        return 1, "Low" if risk_score >= 0.32 else "Safe"

    def _reason_codes(self, analysis, predicted_label: int, combined_risk: float, text_evidence) -> list[str]:
        reasons: list[str] = []
        reasons.extend(analysis.triggered_indicators)
        if combined_risk >= CRITICAL_RISK_THRESHOLD:
            reasons.append("combined_risk_critical")
        elif combined_risk >= HIGH_RISK_THRESHOLD:
            reasons.append("combined_risk_high")
        if text_evidence.top_ngrams:
            reasons.extend([f"tfidf:{ngram}" for ngram in text_evidence.top_ngrams[:5]])
        if predicted_label == 0 and not reasons:
            reasons.append("model_phishing_verdict")
        deduped: list[str] = []
        for reason in reasons:
            if reason not in deduped:
                deduped.append(reason)
        return deduped

    def predict(self, url: str | None = None, features: Dict[str, float] | None = None, source: str = "api") -> Dict:
        if not self.is_ready:
            detail = self._snapshot.load_error or "The model and preprocessor could not be loaded."
            raise RuntimeError(
                "Model artifacts are unavailable. Deploy final_model/model.pkl and "
                f"final_model/preprocessor.pkl, then restart the app. Details: {detail}"
            )

        payload = normalize_feature_payload(url=url, features=features)
        analysis = analyze_url(payload.url)
        text_evidence = get_url_text_risk_model().score(payload.url)
        input_frame = pd.DataFrame([payload.features], columns=self._snapshot.feature_names)
        transformed_frame = self._snapshot.preprocessor.transform(input_frame)
        tabular_phish_prob = self._tabular_probability(transformed_frame)
        combined_risk = self._combine_scores(tabular_phish_prob, analysis.risk_score, text_evidence.score)
        predicted_label, risk_category = self._classify_from_score(combined_risk)
        confidence = combined_risk if predicted_label == 0 else 1.0 - combined_risk
        threat_level, _, score = threat_profile(prediction=predicted_label, confidence=combined_risk)
        prediction_label = "Legitimate" if predicted_label == 1 else "Phishing"
        reason_codes = self._reason_codes(analysis, predicted_label, combined_risk, text_evidence)

        return {
            "url": url or "feature-input",
            "prediction": prediction_label,
            "confidence_score": round(float(confidence), 4),
            "threat_level": threat_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_category": risk_category,
            "score": round(float(score), 4),
            "source": source,
            "reason_codes": reason_codes,
            "heuristic_score": round(float(analysis.risk_score), 4),
            "risk_score": round(float(combined_risk), 4),
            "decision_threshold": DECISION_THRESHOLD,
            "triggered_indicators": analysis.triggered_indicators,
            "suspicious_keywords": analysis.suspicious_terms,
            "brand_hits": analysis.brand_hits,
            "explanation": analysis.explanation,
            "risk_score_breakdown": {
                **analysis.risk_breakdown,
                "tabular_phishing_probability": round(float(tabular_phish_prob), 4),
                "text_ngram_risk": round(float(text_evidence.score), 4),
            },
            "feature_contribution_breakdown": analysis.feature_contributions,
            "text_evidence": {
                "malicious_similarity": text_evidence.malicious_similarity,
                "benign_similarity": text_evidence.benign_similarity,
                "top_ngrams": text_evidence.top_ngrams,
            },
        }

    def predict_dataframe(self, dataframe: pd.DataFrame, source: str = "batch") -> pd.DataFrame:
        if dataframe.empty:
            return pd.DataFrame()

        feature_names = self._snapshot.feature_names
        lower_columns = [column.lower() for column in dataframe.columns]
        if "url" in lower_columns:
            url_column = next(column for column in dataframe.columns if column.lower() == "url")
            records = [self.predict(url=str(row[url_column]), source=source) for _, row in dataframe.iterrows()]
            return pd.DataFrame(records)

        input_frame = dataframe.reindex(columns=feature_names, fill_value=0)
        transformed_frame = self._snapshot.preprocessor.transform(input_frame)

        records = []
        for position, (_, row) in enumerate(dataframe.iterrows()):
            payload_url = str(row.get("url", row.get("URL", f"row-{position}")))
            analysis = analyze_url(payload_url if payload_url else "feature-input")
            text_evidence = get_url_text_risk_model().score(payload_url if payload_url else "feature-input")
            tabular_phish_prob = self._tabular_probability(transformed_frame[position : position + 1])
            combined_risk = self._combine_scores(tabular_phish_prob, analysis.risk_score, text_evidence.score)
            predicted_label, risk_category = self._classify_from_score(combined_risk)
            confidence = combined_risk if predicted_label == 0 else 1.0 - combined_risk
            threat_level, _, score = threat_profile(prediction=predicted_label, confidence=combined_risk)
            records.append(
                {
                    "url": payload_url,
                    "prediction": "Legitimate" if predicted_label == 1 else "Phishing",
                    "confidence_score": round(float(confidence), 4),
                    "threat_level": threat_level,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "risk_category": risk_category,
                    "score": round(float(score), 4),
                    "source": source,
                    "reason_codes": self._reason_codes(analysis, predicted_label, combined_risk, text_evidence),
                    "heuristic_score": round(float(analysis.risk_score), 4),
                    "risk_score": round(float(combined_risk), 4),
                    "decision_threshold": DECISION_THRESHOLD,
                    "triggered_indicators": analysis.triggered_indicators,
                    "suspicious_keywords": analysis.suspicious_terms,
                    "brand_hits": analysis.brand_hits,
                    "explanation": analysis.explanation,
                    "risk_score_breakdown": {
                        **analysis.risk_breakdown,
                        "tabular_phishing_probability": round(float(tabular_phish_prob), 4),
                        "text_ngram_risk": round(float(text_evidence.score), 4),
                    },
                    "feature_contribution_breakdown": analysis.feature_contributions,
                    "text_evidence": {
                        "malicious_similarity": text_evidence.malicious_similarity,
                        "benign_similarity": text_evidence.benign_similarity,
                        "top_ngrams": text_evidence.top_ngrams,
                    },
                }
            )

        return pd.DataFrame(records)

    def get_model_info(self) -> Dict:
        snapshot = self._snapshot
        return {
            "model_name": snapshot.model.__class__.__name__ if snapshot.model else "Unavailable",
            "model_path": str(self.settings.model_path),
            "preprocessor_path": str(self.settings.preprocessor_path),
            "feature_count": len(snapshot.feature_names),
            "trained_artifact_dir": snapshot.latest_artifact_dir,
            "metrics": snapshot.metrics,
            "decision_threshold": DECISION_THRESHOLD,
            "hybrid_detection": True,
            "model_ready": self.is_ready,
            "load_error": snapshot.load_error,
        }

    def get_health_snapshot(self) -> Dict:
        return {
            "status": "healthy" if self.is_ready else "degraded",
            "model_ready": self.is_ready,
            "metrics": self._snapshot.metrics,
        }


model_service = ModelService()
