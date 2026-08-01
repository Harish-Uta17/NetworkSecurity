# PhishGuard AI - Network Security Platform

PhishGuard AI is an end-to-end phishing URL detection platform built with a FastAPI backend, a Streamlit security dashboard, and a scikit-learn machine learning pipeline. It supports real-time URL analysis, CSV batch prediction, threat analytics, model monitoring, and Docker-based deployment.

## Features

- Real-time phishing URL detection with confidence, threat level, and risk category
- Batch CSV prediction for bulk URL or feature-based analysis
- FastAPI backend with interactive Swagger documentation
- Streamlit dashboard for executive insights, live scanning, analytics, model intelligence, and system monitoring
- Prediction history persisted locally as JSONL for analytics and dashboard views
- Reusable training pipeline with ingestion, validation, transformation, and model trainer components
- Docker, Docker Compose, Procfile, and runtime metadata for deployment workflows

## Tech Stack

- Python
- FastAPI
- Streamlit
- scikit-learn
- pandas and NumPy
- Plotly
- MongoDB utilities for data ingestion
- MLflow and DagsHub for experiment tracking
- Docker


## Project Structure

```text
.
|-- app/                         # FastAPI application
|   |-- api/                     # API routers and endpoints
|   |-- core/                    # App config, logging, middleware
|   |-- schemas/                 # Pydantic request/response models
|   `-- services/                # Prediction, analytics, feature, model services
|-- streamlit_app/               # Streamlit dashboard
|-- networksecurity/             # ML pipeline, components, utilities
|-- data_schema/                 # Training schema
|-- final_model/                 # Production model and preprocessor artifacts
|-- Artifacts/                   # Training run artifacts used for model metrics
|-- Network_Data/                # Source dataset for ingestion utilities
|-- scripts/                     # Utility scripts for model/metrics inspection
|-- main.py                      # Legacy/manual training entrypoint
|-- push_data.py                 # MongoDB data upload helper
|-- Dockerfile                   # Container image for API/dashboard code
|-- docker-compose.yml           # Local API + dashboard services
`-- requirements.txt             # Python dependencies
```

## Prerequisites

- Python 3.11 recommended
- Git
- Docker, optional
- MongoDB Atlas connection string, only required for data upload or retraining with MongoDB ingestion

## Environment Variables

Create a local `.env` file when needed:

```env
MONGO_DB_URL=your_mongodb_connection_string
API_BASE_URL=http://127.0.0.1:8000/api/v1
PREDICTION_HISTORY_FILE=logs/prediction_history.jsonl
APP_ENV=development
MAX_UPLOAD_MB=10
```

For hosted deployments, prefer `MONGO_DB_URL` so prediction history survives restarts and is shared across the API and dashboard.

Do not commit `.env` or secrets to GitHub.

## Local Setup

Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

Run the FastAPI backend:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open the API docs:

```text
http://127.0.0.1:8000/docs
```

Run the Streamlit dashboard in a second terminal:

```powershell
streamlit run streamlit_app/app.py
```

Dashboard URL:

```text
http://localhost:8501
```

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/` | Service metadata |
| GET | `/api/v1/health` | API health and model readiness |
| GET | `/api/v1/model-info` | Model paths, feature count, and metrics |
| POST | `/api/v1/predict` | Single URL or feature-map prediction |
| POST | `/api/v1/batch-predict` | CSV upload and batch prediction |
| POST | `/api/v1/upload-csv` | Store CSV and return preview |
| GET | `/api/v1/threat-stats` | Aggregated prediction history |

## Example Prediction Request

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/predict `
  -ContentType "application/json" `
  -Body '{"url":"https://secure-account-verification.example.com/login"}'
```

Example response:

```json
{
  "url": "https://secure-account-verification.example.com/login",
  "prediction": "Phishing",
  "confidence_score": 0.91,
  "threat_level": "High",
  "timestamp": "2026-05-22T10:30:00Z",
  "risk_category": "Critical",
  "score": 0.94,
  "source": "api"
}
```

## Batch Prediction

Upload a CSV through the dashboard or call the API:

```powershell
curl.exe -X POST `
  -F "file=@sample_urls.csv" `
  http://127.0.0.1:8000/api/v1/batch-predict
```

The CSV can contain a `url` column. If no URL column exists, the service expects columns compatible with the trained feature schema.

## Docker Usage

Build and run the API container:

```powershell
docker build -t phishguard-ai .
docker run --env-file .env -p 8000:8000 phishguard-ai
```

Run API and dashboard together:

```powershell
docker compose up --build
```

Services:

- API: `http://localhost:8000`
- Dashboard: `http://localhost:8501`

## Training Pipeline

The original training workflow is available through `main.py`:

```powershell
python main.py
```

The pipeline includes:

- Data ingestion
- Data validation against `data_schema/schema.yaml`
- Data transformation
- Model training
- Final artifact export to `final_model/`

The production API loads:

```text
final_model/model.pkl
final_model/preprocessor.pkl
```

## MLflow Tracking

The model trainer integrates with DagsHub/MLflow. To use a local MLflow backend:

```powershell
$env:MLFLOW_TRACKING_URI = "sqlite:///mlflow.db"
mlflow ui --backend-store-uri sqlite:///mlflow.db --host 127.0.0.1 --port 5000
```

`mlflow.db` is a local runtime artifact and should not be committed.

## Deployment Notes

This repository includes:

- `Dockerfile` for container deployment
- `docker-compose.yml` for local multi-service execution
- `Procfile` for platforms such as Render or Railway
- `runtime.txt` for Python runtime selection

The default production command is:

```text
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

If you deploy the Streamlit dashboard separately from the FastAPI backend, set `API_BASE_URL` so the dashboard reads threat stats and history from the API instead of its local fallback store. For persistent history across restarts, configure `MONGO_DB_URL` so the prediction store can use MongoDB.

## Git Hygiene

The repository intentionally ignores local/generated files such as:

- `.env`
- `venv/`
- `logs/`
- `uploads/`
- `__pycache__/`
- `*.pyc`
- local database files such as `*.db`

Before pushing to GitHub, verify:

```powershell
git status --short
```

## License

Add a license file before public distribution if this project will be shared or reused by others.
