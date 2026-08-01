from datetime import datetime, timezone
import time

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.prediction import HealthResponse
from app.services.model_service import model_service
from app.services.prediction_store import prediction_store


router = APIRouter()
START_TIME = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    settings = get_settings()
    health = model_service.get_health_snapshot()
    return HealthResponse(
        status=health["status"],
        environment=settings.environment,
        model_ready=health["model_ready"],
        history_backend=prediction_store.backend_name,
        timestamp=datetime.now(timezone.utc),
        uptime_seconds=round(time.time() - START_TIME, 2),
    )
