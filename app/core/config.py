from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import os


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class AppSettings:
    app_name: str = "NetworkSecurity AI Cybersecurity Platform"
    version: str = "1.0.0"
    description: str = (
        "Enterprise phishing and suspicious URL detection API with analytics, "
        "history tracking, and production-ready prediction endpoints."
    )
    environment: str = os.getenv("APP_ENV", "development")
    api_prefix: str = "/api/v1"
    # Override this when the app is run outside the repository layout.
    model_dir: Path = Path(os.getenv("MODEL_DIR", str(PROJECT_ROOT / "final_model")))
    artifacts_dir: Path = PROJECT_ROOT / "Artifacts"
    uploads_dir: Path = PROJECT_ROOT / "uploads"
    logs_dir: Path = PROJECT_ROOT / "logs"
    history_file: Path = Path(os.getenv("PREDICTION_HISTORY_FILE", str(PROJECT_ROOT / "logs" / "prediction_history.jsonl")))
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "10"))
    swagger_theme: str = os.getenv("SWAGGER_THEME", "dark")

    @property
    def model_path(self) -> Path:
        return self.model_dir / "model.pkl"

    @property
    def preprocessor_path(self) -> Path:
        return self.model_dir / "preprocessor.pkl"

    @property
    def upload_limit_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()
