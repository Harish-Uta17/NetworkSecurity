# 🛡️ PhishGuard AI

**AI-powered phishing URL detection and cyber threat intelligence platform.**

PhishGuard AI is an end-to-end machine learning system that classifies URLs as **phishing** or **legitimate** and surfaces enterprise-grade threat intelligence. It combines a trained ML model with URL heuristics and TF-IDF text analysis into a **hybrid detector**, exposes everything through a **FastAPI** service, and ships with a polished **Streamlit** security console — backed by a reproducible **MLOps training pipeline** with MongoDB ingestion, data validation/drift reporting, and MLflow experiment tracking.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-1.8.0-F7931E?logo=scikitlearn&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi&logoColor=white">
  <img alt="Streamlit" src="https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit&logoColor=white">
  <img alt="MLflow" src="https://img.shields.io/badge/MLflow-Tracking-0194E2?logo=mlflow&logoColor=white">
  <img alt="MongoDB" src="https://img.shields.io/badge/MongoDB-Atlas-47A248?logo=mongodb&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Container-2496ED?logo=docker&logoColor=white">
</p>

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Model Performance](#-model-performance)
- [Project Structure](#-project-structure)
- [The ML Training Pipeline](#-the-ml-training-pipeline)
- [The Hybrid Detection Engine](#-the-hybrid-detection-engine)
- [REST API Reference](#-rest-api-reference)
- [The Streamlit Dashboard](#-the-streamlit-dashboard)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [Running with Docker](#-running-with-docker)
- [Deployment](#-deployment)
- [Author](#-author)

---

## ✨ Key Features

- **Real-time URL detection** — paste a URL and get an instant phishing/legitimate verdict with a confidence score, risk level, and AI explanation.
- **Hybrid detection engine** — fuses a trained tabular ML model, rule-based URL heuristics, and TF-IDF text similarity into a single calibrated risk score.
- **End-to-end MLOps pipeline** — automated data ingestion (MongoDB → feature store), schema validation with drift reporting, KNN-imputed transformation, multi-model training with hyperparameter search, and versioned artifacts.
- **Experiment tracking** — MLflow metrics logged to a DagsHub-hosted tracking server.
- **Production REST API** — FastAPI service with single & batch prediction, CSV upload, history, threat statistics, model info, and health endpoints (auto-generated Swagger docs at `/docs`).
- **Enterprise security console** — a multi-page Streamlit dashboard (executive overview, real-time scanner, threat analytics, batch scanning, model intelligence, system monitoring).
- **Durable prediction history** — MongoDB-backed storage with an automatic local-file fallback.
- **Batch scanning** — upload a CSV of URLs and download scored results.
- **Explainability** — per-prediction triggered indicators, suspicious keywords, risk-score breakdown, feature-contribution chart, and TF-IDF evidence.
- **Container-ready** — Dockerfile + docker-compose for the API and dashboard, plus Procfile/runtime for PaaS deploys.

---

## 🏗 Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │              TRAINING PIPELINE                 │
                         │  (networksecurity/)                            │
                         │                                                │
   MongoDB ── ingest ──▶ │ Data Ingestion → Validation (drift report) →   │
   (raw URL data)        │ Transformation (KNN imputer) → Model Trainer   │
                         │ → best model selected via grid search          │
                         └───────────────┬────────────────────────────────┘
                                         │ artifacts
                                         ▼
                              final_model/model.pkl
                              final_model/preprocessor.pkl
                              final_model/metrics.json
                                         │
             ┌───────────────────────────┼───────────────────────────┐
             ▼                                                         ▼
   ┌──────────────────────┐                              ┌───────────────────────────┐
   │  FastAPI Service      │                              │  Streamlit Dashboard        │
   │  (app/)               │◀────── optional API_BASE_URL─│  (streamlit_app/)           │
   │                       │                              │                             │
   │  /predict             │       Hybrid Detector        │  Executive · Real-Time ·    │
   │  /batch-predict       │  ┌────────────────────────┐  │  Analytics · Batch ·        │
   │  /history /stats      │  │ ML model + URL heuristics│  │  Model Intelligence ·      │
   │  /model-info /health  │  │ + TF-IDF text analysis  │  │  System Monitoring          │
   └───────────┬───────────┘  └────────────────────────┘  └──────────────┬─────────────┘
               │                                                          │
               └──────────────► Prediction Store (MongoDB / file) ◀───────┘
```

The FastAPI service and Streamlit dashboard share the same service layer (`app/services/`). The dashboard can either call the API (via `API_BASE_URL`) or run the model in-process, so it works as a standalone app or as a full client/server deployment.

---

## 🧰 Tech Stack

| Layer | Technologies |
|------|--------------|
| **Language** | Python 3.11 |
| **ML / Data** | scikit-learn 1.8, pandas, NumPy |
| **Experiment tracking** | MLflow + DagsHub |
| **Backend API** | FastAPI, Uvicorn, Pydantic |
| **Dashboard** | Streamlit, Plotly |
| **Database** | MongoDB Atlas (`pymongo[srv]`) |
| **Cloud / Storage** | AWS S3 syncer, Docker, docker-compose |
| **Monitoring** | psutil (host utilization) |

---

## 📊 Model Performance

The production model is a depth-capped **Random Forest** selected automatically from a candidate set (Random Forest, Gradient Boosting, Decision Tree, Logistic Regression, AdaBoost) via grid search, trained on a **balanced ~250k-row dataset**.

| Metric | Test Score |
|--------|-----------|
| **Accuracy** | 0.944 |
| **Precision** | 0.951 |
| **Recall** | 0.936 |
| **F1 Score** | 0.944 |

> Trees are constrained (`max_depth`, `min_samples_leaf`) to keep the serialized model lightweight for cloud deployment while preserving accuracy. Evaluation metrics are persisted to `final_model/metrics.json` and surfaced on the dashboard's **Model Intelligence** page.

---

## 📁 Project Structure

```
PhishGuard-AI/
├── app/                              # FastAPI application
│   ├── main.py                       # App factory, CORS, exception handlers
│   ├── api/
│   │   ├── router.py                 # Aggregates all route groups
│   │   └── routes/
│   │       ├── health.py             # GET /health
│   │       ├── model.py              # GET /model-info
│   │       ├── predictions.py        # POST /predict, /batch-predict, /upload-csv
│   │       └── stats.py              # GET /threat-stats, /history
│   ├── core/
│   │   ├── config.py                 # Typed settings (paths, env, thresholds)
│   │   ├── logging.py                # App logging config
│   │   └── middleware.py             # Request-context middleware
│   ├── schemas/prediction.py         # Pydantic request/response models
│   └── services/
│       ├── model_service.py          # Model loading, inference, metrics snapshot
│       ├── feature_engineering.py    # URL → feature vector
│       ├── url_analysis.py           # Heuristic + TF-IDF URL analysis
│       ├── threat_scoring.py         # Risk-level / threat-profile mapping
│       ├── analytics.py              # Threat statistics aggregation
│       └── prediction_store.py       # MongoDB store w/ file fallback
│
├── networksecurity/                  # Reusable ML pipeline package
│   ├── components/
│   │   ├── data_ingestion.py         # MongoDB → feature store → train/test split
│   │   ├── data_validation.py        # Schema check + drift report
│   │   ├── data_transformation.py    # KNN imputer + preprocessing pipeline
│   │   └── model_trainer.py          # Multi-model grid search + MLflow logging
│   ├── pipeline/
│   │   ├── training_pipeline.py      # Orchestrates the full pipeline
│   │   └── batch_prediction.py
│   ├── entity/                       # Config & artifact dataclasses
│   ├── constant/training_pipeline/   # Pipeline constants
│   ├── cloud/s3_syncer.py            # Push/pull artifacts to S3
│   ├── utils/                        # I/O helpers, metrics, estimator wrapper
│   ├── exception/ · logging/         # Custom exceptions & logger
│
├── streamlit_app/app.py              # Multi-page security dashboard
├── final_model/                      # Deployed artifacts
│   ├── model.pkl · preprocessor.pkl · metrics.json
├── data_schema/schema.yaml           # Feature schema & types
├── Network_Data/balanced_dataset.csv # Training dataset
├── scripts/                          # Benchmarking & evaluation utilities
├── main.py                           # Legacy training entrypoint
├── push_data.py                      # Load raw data into MongoDB
├── test_mongodb.py                   # MongoDB connectivity check
├── Dockerfile · docker-compose.yml   # Containerization
├── Procfile · runtime.txt            # PaaS deploy config
└── requirements.txt · setup.py
```

---

## 🔬 The ML Training Pipeline

Run end-to-end from `networksecurity/pipeline/training_pipeline.py` (or the legacy `main.py`). Stages:

1. **Data Ingestion** — pulls raw records from MongoDB, writes a feature store, and performs a stratified train/test split (80/20).
2. **Data Validation** — validates columns/types against `data_schema/schema.yaml` and generates a **drift report**.
3. **Data Transformation** — imputes missing values with a **KNN imputer** (`n_neighbors=3`) and fits the preprocessing pipeline, saving `preprocessor.pkl` and transformed `train.npy` / `test.npy`.
4. **Model Training** — grid-searches multiple classifiers, selects the best by score (subject to an expected-accuracy threshold and over/under-fitting guard), refits it, logs metrics to **MLflow/DagsHub**, and writes `model.pkl` + `metrics.json`.

Each run is versioned under `Artifacts/<timestamp>/`, and the promoted artifacts are copied to `final_model/` for serving.

**URL feature schema** (`data_schema/schema.yaml`) includes: `url_length`, `domain_length`, `tld`, `url_entropy`, `sub_domain`, `digit_count`, `special_char_count`, `slash_count`, `https_flag`, `domain_entropy`, `keyword_flag`, `ip_flag`, `hyphen_count`, `query_length`, `at_flag` — with `label` as the target.

---

## 🧪 The Hybrid Detection Engine

Rather than relying on the ML model alone, PhishGuard fuses three signals for a more robust, explainable verdict:

1. **Tabular ML probability** — the trained classifier's phishing probability from engineered URL features.
2. **URL heuristics** (`url_analysis.py`) — rule-based checks: IP-in-host, `@` symbol, excessive sub-domains, suspicious keywords, brand impersonation, entropy, hyphenation, etc. → triggered indicators.
3. **TF-IDF text analysis** — character/word n-gram similarity of the URL against malicious vs. benign corpora → text-evidence score.

These are combined in `model_service._combine_scores()` into a final **risk score**, mapped to a threat level and risk category, and returned with a full explanation (triggered indicators, suspicious keywords, risk-score breakdown, feature contributions, and TF-IDF evidence).

---

## 🌐 REST API Reference

Base prefix: `/api/v1` · Interactive docs: `/docs` (Swagger) · `/redoc`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health` | Service status, model readiness, history backend, uptime |
| `GET`  | `/model-info` | Model name, paths, feature count, metrics, threshold |
| `POST` | `/predict` | Score a single URL (or raw feature map) |
| `POST` | `/batch-predict` | Score a CSV of URLs, returns summary + records |
| `POST` | `/upload-csv` | Upload a CSV and preview it |
| `GET`  | `/history?limit=` | Recent prediction history |
| `GET`  | `/threat-stats` | Aggregated threat statistics |

**Example — single prediction:**

```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://secure-account-verification.example.com/login"}'
```

```json
{
  "url": "https://secure-account-verification.example.com/login",
  "prediction": "Phishing",
  "confidence_score": 0.94,
  "threat_level": "High",
  "risk_category": "Critical",
  "risk_score": 0.91,
  "triggered_indicators": ["brand_impersonation", "random_domain_pattern"],
  "suspicious_keywords": ["secure", "verification", "login"],
  "explanation": "High-entropy URL structure with brand-impersonation signals."
}
```

---

## 🖥 The Streamlit Dashboard

A cyber-themed, fully responsive security console (`streamlit_app/app.py`) with seven pages:

- **🧭 Executive Dashboard** — KPIs, threat overview, and history backend status.
- **⚡ Real-Time URL Detection** — scan a URL and view threat status, dual confidence/risk gauges, indicators, keywords, and explainability charts.
- **📈 Threat Analytics** — trends, threat concentrations, and risk posture over time.
- **🗂️ Batch Prediction** — upload a CSV, scan in bulk, download scored results.
- **🧠 Model Intelligence** — accuracy/precision/recall/F1, confusion matrix, and feature importance.
- **🛰️ System Monitoring** — host CPU/memory/disk utilization and model health.
- **ℹ️ About Project** — architecture and stack.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11
- A MongoDB connection string (Atlas or local) — optional but recommended for durable history

### Installation

```bash
git clone https://github.com/Harish-Uta17/PhishGuard-AI.git
cd PhishGuard-AI

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### (Optional) Train the model

```bash
python main.py          # runs the full ingestion → validation → transformation → training pipeline
```

Trained artifacts are written to `final_model/`.

### Run the API

```bash
uvicorn app.main:app --reload --port 8000
# Docs: http://localhost:8000/docs
```

### Run the dashboard

```bash
streamlit run streamlit_app/app.py
```

---

## ⚙️ Configuration

Set via environment variables or a `.env` file (see `app/core/config.py`):

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGO_DB_URL` | MongoDB connection string (enables durable history) | — |
| `PREDICTION_HISTORY_DB` | Mongo database for history | `networksecurity` |
| `PREDICTION_HISTORY_COLLECTION` | Mongo collection for history | `prediction_history` |
| `PREDICTION_HISTORY_FILE` | Local fallback JSONL path | `logs/prediction_history.jsonl` |
| `MODEL_DIR` | Directory holding `model.pkl` / `preprocessor.pkl` | `final_model` |
| `API_BASE_URL` | If set, the dashboard calls the API instead of running the model in-process | — |
| `APP_TIMEZONE` | Display timezone | `Asia/Kolkata` |

> **Note:** For durable history on the cloud, provide `MONGO_DB_URL` **and** allowlist your host's IP in MongoDB Atlas (Network Access). Without a reachable database, the app falls back to local file storage, which is ephemeral on most cloud platforms.

---

## 🐳 Running with Docker

Run the API and dashboard together:

```bash
docker-compose up --build
```

- API → http://localhost:8000
- Dashboard → http://localhost:8501 (pre-wired to the API via `API_BASE_URL`)

Or build the single image:

```bash
docker build -t phishguard-ai .
docker run -p 8000:8000 phishguard-ai
```

---

## ☁️ Deployment

- **API (PaaS/Docker):** `Procfile` and `runtime.txt` are included for platforms like Render/Railway/Heroku; the Dockerfile targets any container host.
- **Dashboard (Streamlit Community Cloud):** point it at `streamlit_app/app.py` and add `MONGO_DB_URL` (and related keys) in **Secrets**. Since `final_model/*.pkl` are committed, the app loads the model directly on a fresh clone.
- **Artifacts on S3:** `networksecurity/cloud/s3_syncer.py` can push/pull training artifacts and models to an S3 bucket for larger-scale deployments.

---

## 👤 Author

**Harish Kumar Uta**
- GitHub: [@Harish-Uta17](https://github.com/Harish-Uta17)

---

<p align="center"><i>Built as an end-to-end MLOps + full-stack security project — from raw data in MongoDB to a deployed, explainable phishing-detection platform.</i></p>