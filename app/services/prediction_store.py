from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import logging
import os
from pathlib import Path
from threading import Lock
from typing import Dict, List

try:
    from pymongo import MongoClient
except Exception:  # pragma: no cover - optional dependency in some deployments
    MongoClient = None

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class PredictionStore:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.path = Path(self.settings.history_file)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self.mongo_uri = os.getenv("MONGO_DB_URL", "").strip()
        self.mongo_database = os.getenv("PREDICTION_HISTORY_DB", "networksecurity")
        self.mongo_collection = os.getenv("PREDICTION_HISTORY_COLLECTION", "prediction_history")
        self._mongo_collection = None
        self.mongo_error: str | None = None

        if self.mongo_uri and MongoClient is not None:
            try:
                client = MongoClient(
                    self.mongo_uri,
                    serverSelectionTimeoutMS=3000,
                    connectTimeoutMS=3000,
                    socketTimeoutMS=5000,
                )
                # MongoClient connects lazily. Ping once at startup so an
                # unreachable Atlas instance does not stall every read/write.
                client.admin.command("ping")
                self._mongo_collection = client[self.mongo_database][self.mongo_collection]
            except Exception as exc:
                self._mongo_collection = None
                self.mongo_error = f"{type(exc).__name__}: {exc}"
                logger.warning("Mongo connection failed; using file storage: %s", self.mongo_error)

    @property
    def backend_name(self) -> str:
        return "mongo" if self._mongo_collection is not None else "file"

    def _normalize_record(self, record: Dict) -> Dict:
        payload = dict(record)
        payload.setdefault("timestamp", datetime.utcnow().isoformat())
        timestamp = payload.get("timestamp")
        if isinstance(timestamp, datetime):
            payload["timestamp"] = timestamp.isoformat()
        else:
            payload["timestamp"] = str(timestamp)
        return payload

    def append(self, record: Dict) -> None:
        payload = self._normalize_record(record)
        with self._lock:
            if self._mongo_collection is not None:
                try:
                    self._mongo_collection.insert_one(payload)
                except Exception as exc:
                    self._mongo_collection = None
                    self.mongo_error = f"{type(exc).__name__}: {exc}"
                    logger.warning(self.mongo_error)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, default=str) + "\n")

    def load(self, limit: int | None = None) -> List[Dict]:
        if self._mongo_collection is not None:
            try:
                cursor = self._mongo_collection.find({}, {"_id": 0}).sort("timestamp", -1)
                if limit:
                    cursor = cursor.limit(limit)
                rows = list(cursor)
                return list(reversed(rows))
            except Exception as exc:
                self._mongo_collection = None
                self.mongo_error = f"{type(exc).__name__}: {exc}"
                logger.warning("Mongo history read failed; switched to file storage: %s", self.mongo_error)

        if not self.path.exists():
            return []

        with self.path.open("r", encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]

        return rows[-limit:] if limit else rows

    def summary(self, limit: int = 100) -> Dict:
        rows = self.load(limit=limit)
        threat_counter = Counter(row.get("threat_level", "Unknown") for row in rows)
        risk_counter = Counter(row.get("risk_category", "Unknown") for row in rows)
        phishing_count = sum(1 for row in rows if row.get("prediction") == "Phishing")
        legitimate_count = sum(1 for row in rows if row.get("prediction") == "Legitimate")
        avg_confidence = round(
            sum(float(row.get("confidence_score", 0)) for row in rows) / len(rows), 4
        ) if rows else 0.0
        return {
            "total_predictions": len(rows),
            "phishing_count": phishing_count,
            "legitimate_count": legitimate_count,
            "average_confidence": avg_confidence,
            "by_threat_level": dict(threat_counter),
            "by_risk_category": dict(risk_counter),
            "recent_predictions": rows[-10:],
        }


prediction_store = PredictionStore()
