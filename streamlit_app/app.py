from __future__ import annotations

from datetime import datetime, timezone
import io
from pathlib import Path
import os
import re
import sys
import time
from typing import Dict, List
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# The repo contains a top-level `app.py` which can shadow the `app/` package.
# Load the service modules directly from the `app/services` folder by file path
# to avoid import-time shadowing errors when Streamlit runs.
import importlib.util
import types


def _load_module_from_path(mod_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def _load_streamlit_secrets_into_environment() -> None:
    """Make Streamlit Cloud secrets available to the shared service layer."""
    try:
        for key in ("MONGO_DB_URL", "PREDICTION_HISTORY_DB", "PREDICTION_HISTORY_COLLECTION"):
            if key not in os.environ and key in st.secrets:
                os.environ[key] = str(st.secrets[key])
    except Exception:
        # Local runs without .streamlit/secrets.toml should continue normally.
        pass


_load_streamlit_secrets_into_environment()


APP_NAME = "PhishGuard AI"
APP_TAGLINE = "AI-powered phishing URL detection and cyber threat intelligence"
LOCAL_TIMEZONE = ZoneInfo(os.getenv("APP_TIMEZONE", "Asia/Kolkata"))
LOCAL_TIMEZONE_LABEL = os.getenv("APP_TIMEZONE_LABEL", "IST")
NAV_ITEMS = [
    {"title": "Executive Dashboard", "icon": "🧭", "subtitle": "Operations overview"},
    {"title": "Real-Time URL Detection", "icon": "⚡", "subtitle": "Instant analysis"},
    {"title": "Threat Analytics", "icon": "📈", "subtitle": "Trends and risk"},
    {"title": "Batch Prediction", "icon": "🗂️", "subtitle": "Bulk scanning"},
    {"title": "Model Intelligence", "icon": "🧠", "subtitle": "Metrics and features"},
    {"title": "System Monitoring", "icon": "🛰️", "subtitle": "Health and logs"},
    {"title": "About Project", "icon": "ℹ️", "subtitle": "Architecture and stack"},
]

SAMPLE_PHISHING_URLS = [
    "https://secure-account-verification.example.com/login",
    "https://billing-update.example.net/confirm-payment",
    "https://office365-security-alert.example.org/reset",
    "https://cloud-storage-access.example.io/session-check",
]


_services_dir = PROJECT_ROOT / "app" / "services"
if "app" not in sys.modules or not getattr(sys.modules.get("app"), "__path__", None):
    app_pkg = types.ModuleType("app")
    app_pkg.__path__ = [str(PROJECT_ROOT / "app")]
    sys.modules["app"] = app_pkg
_analytics_mod = _load_module_from_path("app.services.analytics", _services_dir / "analytics.py")
build_threat_statistics = getattr(_analytics_mod, "build_threat_statistics")

_model_mod = _load_module_from_path("app.services.model_service", _services_dir / "model_service.py")
model_service = getattr(_model_mod, "model_service")

_pred_mod = _load_module_from_path("app.services.prediction_store", _services_dir / "prediction_store.py")
prediction_store = getattr(_pred_mod, "prediction_store")


CYBER_CSS = """
<style>
:root {
    --bg: #050b15;
    --bg-alt: #081321;
    --panel: rgba(11, 22, 40, 0.82);
    --panel-strong: rgba(14, 28, 50, 0.96);
    --border: rgba(45, 255, 243, 0.16);
    --border-strong: rgba(111, 147, 255, 0.22);
    --accent: #27f5ee;
    --accent-2: #6d7cff;
    --accent-3: #9b5cff;
    --good: #10b981;
    --warn: #f59e0b;
    --danger: #ff4d6d;
    --text: #eaf3ff;
    --muted: #8da4c0;
    --shadow: 0 24px 72px rgba(0, 0, 0, 0.34);
    /* consistent scale so spacing/rounding is uniform everywhere */
    --r-sm: 12px;
    --r-md: 16px;
    --r-lg: 20px;
    --r-xl: 24px;
    --pad-card: 1.15rem;
    --gap: 0.9rem;
}

html, body, [class*="css"] {
    font-family: Inter, "Segoe UI", system-ui, -apple-system, sans-serif;
}

html, body { overflow-x: hidden; }
body { background: var(--bg); }

.stApp {
    background:
        radial-gradient(circle at 12% 10%, rgba(39, 245, 238, 0.10), transparent 24%),
        radial-gradient(circle at 86% 2%, rgba(155, 92, 255, 0.14), transparent 26%),
        linear-gradient(180deg, #07111f 0%, #050b15 56%, #040810 100%);
    color: var(--text);
    overflow-x: hidden;
}

[data-testid="stAppViewBlockContainer"], [data-testid="stAppViewContainer"] { width: 100%; min-width: 0; }
[data-testid="stAppViewBlockContainer"] { display: flex; align-items: stretch; }
[data-testid="stAppViewContainer"] { flex: 1 1 auto; min-width: 0; }
[data-testid="stAppViewContainer"] > .main { width: 100%; min-width: 0; flex: 1 1 auto; padding-left: 0; padding-right: 0; }

.block-container {
    padding-top: 1.1rem;
    padding-bottom: 2.2rem;
    max-width: 1480px;
    margin: 0 auto;
    width: 100%;
    padding-left: clamp(1rem, 1.8vw, 2rem);
    padding-right: clamp(1rem, 1.8vw, 2rem);
}

[data-testid="stSidebar"] {
    flex: 0 0 318px;
    width: 318px !important;
    min-width: 318px !important;
    max-width: 318px !important;
    border-right: 1px solid rgba(45, 255, 243, 0.08);
    transition: width 240ms ease, min-width 240ms ease, max-width 240ms ease, transform 240ms ease, opacity 240ms ease;
    overflow: hidden;
}

[data-testid="stSidebar"][aria-expanded="false"] {
    flex: 0 0 0 !important;
    width: 0 !important;
    min-width: 0 !important;
    max-width: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
    border-right: 0 !important;
    opacity: 0;
    transform: translateX(-100%);
    pointer-events: none;
}

[data-testid="stSidebar"][aria-expanded="false"] > div { display: none; }
[data-testid="stSidebarContent"] { padding-top: 0.9rem; }
.stSidebar { background: linear-gradient(180deg, rgba(7, 14, 26, 0.98), rgba(5, 9, 17, 0.98)); }

#MainMenu,
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
[data-testid="stDeployButton"] {
    display: none !important;
    visibility: hidden !important;
}

[data-testid="stHeader"] { background: transparent !important; }

[data-testid="stToolbar"] { right: clamp(1rem, 1.8vw, 1.9rem); }
[data-testid="stToolbar"] [data-testid="stDeployButton"],
[data-testid="stToolbar"] [data-testid="stBaseButton-header"],
[data-testid="stToolbar"] [aria-label="Deploy"],
[data-testid="stToolbar"] [title="Deploy"],
[data-testid="stToolbar"] [aria-label="Main menu"],
[data-testid="stToolbar"] [aria-label="More options"] {
    display: none !important;
    visibility: hidden !important;
}

[data-testid="collapsedControl"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    z-index: 1002 !important;
}

/* Equal-height columns + consistent gaps everywhere */
div[data-testid="stHorizontalBlock"] { gap: var(--gap); align-items: stretch; }
div[data-testid="column"], div[data-testid="stColumn"] { display: flex; }
div[data-testid="column"] > div, div[data-testid="stColumn"] > div { width: 100%; display: flex; flex-direction: column; }
/* make direct card children fill the column height so rows line up */
div[data-testid="column"] > div > [class$="-card"],
div[data-testid="stColumn"] > div > [class$="-card"] { height: 100%; }

.sidebar-shell {
    border: 1px solid rgba(45, 255, 243, 0.12);
    border-radius: var(--r-xl);
    padding: 1.05rem 1.1rem;
    background: linear-gradient(180deg, rgba(10, 20, 36, 0.96), rgba(7, 13, 24, 0.96));
    box-shadow: var(--shadow);
}

.sidebar-brand { display: flex; align-items: center; gap: 0.75rem; }
.brand-mark {
    width: 42px; height: 42px; display: inline-flex; align-items: center; justify-content: center;
    border-radius: 14px; background: linear-gradient(135deg, rgba(39, 245, 238, 0.2), rgba(109, 124, 255, 0.22));
    border: 1px solid rgba(45, 255, 243, 0.24); box-shadow: 0 10px 24px rgba(39, 245, 238, 0.12); font-size: 1.15rem; flex: 0 0 42px;
}
.brand-kicker { color: var(--accent); text-transform: uppercase; letter-spacing: 0.22em; font-size: 0.72rem; font-weight: 800; }
.brand-title { color: var(--text); font-size: 1.28rem; font-weight: 800; margin-top: 0.25rem; line-height: 1.2; }
.brand-subtitle { color: var(--muted); font-size: 0.86rem; line-height: 1.45; margin-top: 0.35rem; }
.brand-description { color: var(--muted); font-size: 0.82rem; line-height: 1.55; margin-top: 0.55rem; }
.brand-description strong { color: var(--text); }
.nav-badge { display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 999px; border: 1px solid rgba(45, 255, 243, 0.18); padding: 0.38rem 0.72rem; font-size: 0.78rem; color: var(--text); background: rgba(39, 245, 238, 0.08); }
.nav-header { margin: 0.35rem 0 0.65rem; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.16em; font-weight: 800; }
.nav-hint { color: var(--muted); font-size: 0.78rem; line-height: 1.45; margin: 0.2rem 0 0.55rem; }

.stRadio label { color: var(--text) !important; }
.stRadio [role="radiogroup"] { gap: 0.42rem; }
.stRadio [role="radiogroup"] > label {
    background: rgba(14, 25, 43, 0.82);
    border: 1px solid rgba(45, 255, 243, 0.10);
    border-radius: 14px;
    padding: 0.72rem 0.82rem;
    align-items: flex-start;
    transition: transform 140ms ease, border-color 140ms ease, background 140ms ease, box-shadow 140ms ease;
}
.stRadio [role="radiogroup"] > label:hover { transform: translateY(-1px); border-color: rgba(45, 255, 243, 0.26); box-shadow: 0 14px 28px rgba(0, 0, 0, 0.18); }
.stRadio [role="radiogroup"] > label[data-checked="true"] { background: linear-gradient(135deg, rgba(39, 245, 238, 0.15), rgba(109, 124, 255, 0.14)); border-color: rgba(45, 255, 243, 0.35); }
.stRadio [data-baseweb="radio"] { margin-right: 0.65rem; }
.stRadio [role="radiogroup"] span { line-height: 1.2; }

.nav-option-title { display: block; font-size: 0.92rem; font-weight: 750; line-height: 1.15; }
.nav-option-subtitle { display: block; margin-top: 0.2rem; color: var(--muted); font-size: 0.75rem; line-height: 1.2; white-space: pre-line; }

.hero-card,
.panel-card,
.insight-card,
.empty-card,
.surface-card {
    background: linear-gradient(180deg, rgba(13, 26, 45, 0.94), rgba(8, 16, 31, 0.94));
    border: 1px solid rgba(45, 255, 243, 0.12);
    border-radius: var(--r-xl);
    box-shadow: var(--shadow);
}

.hero-card { padding: 1.5rem 1.6rem; position: relative; overflow: hidden; margin-bottom: 1.1rem; }
.hero-card:before { content: ""; position: absolute; inset: 0; background: radial-gradient(circle at top right, rgba(39, 245, 238, 0.12), transparent 34%); pointer-events: none; }
.hero-stack { position: relative; z-index: 1; display: flex; justify-content: space-between; gap: 1.1rem; flex-wrap: wrap; align-items: flex-start; }
.hero-copy { max-width: 72ch; }
.eyebrow { color: var(--accent); text-transform: uppercase; letter-spacing: 0.2em; font-size: 0.72rem; font-weight: 800; }
.hero-title { margin: 0.3rem 0 0.4rem; font-size: clamp(1.8rem, 3vw, 2.7rem); line-height: 1.05; color: var(--text); font-weight: 850; }
.hero-subtitle { color: var(--muted); max-width: 64ch; line-height: 1.6; font-size: 1.02rem; }
.hero-description { color: #c9d7ea; font-size: 0.96rem; line-height: 1.7; max-width: 68ch; margin-top: 0.9rem; }
.hero-description strong { color: var(--text); }
.hero-actions { position: relative; z-index: 1; display: flex; gap: 0.65rem; flex-wrap: wrap; margin-top: 1rem; }
.hero-action-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.7rem; margin-top: 1rem; position: relative; z-index: 1; }
.hero-cta { display: inline-flex; align-items: center; justify-content: center; gap: 0.45rem; min-height: 46px; padding: 0.7rem 1rem; border-radius: 14px; border: 1px solid rgba(45, 255, 243, 0.16); text-decoration: none; font-size: 0.88rem; font-weight: 800; letter-spacing: 0.01em; transition: transform 140ms ease, box-shadow 140ms ease, border-color 140ms ease, background 140ms ease; }
.hero-cta.primary { color: #03101d; background: linear-gradient(90deg, #27f5ee, #6d7cff); box-shadow: 0 16px 30px rgba(39, 245, 238, 0.16); }
.hero-cta.secondary { color: var(--text); background: rgba(14, 25, 43, 0.84); }
.hero-cta:hover { transform: translateY(-1px); border-color: rgba(45, 255, 243, 0.26); }
.status-row { display: flex; gap: 0.5rem; flex-wrap: wrap; justify-content: flex-end; align-items: center; }
.hero-metrics { position: relative; z-index: 1; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.7rem; margin-top: 1.1rem; }
.hero-metric { border: 1px solid rgba(45, 255, 243, 0.12); border-radius: var(--r-md); padding: 0.85rem 0.9rem; background: rgba(11, 22, 40, 0.72); display: flex; flex-direction: column; }
.hero-metric-label { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 800; }
.hero-metric-value { color: var(--text); margin-top: 0.35rem; font-size: 1.15rem; font-weight: 850; }
.hero-metric-note { color: var(--muted); margin-top: auto; padding-top: 0.15rem; font-size: 0.8rem; }

.pill,
.severity-pill,
.status-pill { display: inline-flex; align-items: center; gap: 0.45rem; border-radius: 999px; padding: 0.45rem 0.8rem; font-size: 0.8rem; font-weight: 700; border: 1px solid rgba(45, 255, 243, 0.14); line-height: 1; }
.pill { background: rgba(39, 245, 238, 0.08); color: #a8ffff; }
.pill.good { background: rgba(16, 185, 129, 0.12); color: #8ff0c7; }
.pill.warn { background: rgba(245, 158, 11, 0.12); color: #f8cd76; }
.pill.danger { background: rgba(255, 77, 109, 0.14); color: #ffb0bf; }
.analysis-time { margin: 0.2rem 0 0.85rem; }
.analysis-time .pill { font-size: 0.86rem; padding: 0.5rem 0.95rem; }

.section-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; margin: 0.5rem 0 1rem; flex-wrap: wrap; }
.section-title { margin: 0; font-size: 1.18rem; font-weight: 750; color: var(--text); line-height: 1.2; }
.section-subtitle { color: var(--muted); font-size: 0.9rem; margin-top: 0.3rem; line-height: 1.4; }

.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: var(--gap); align-items: stretch; }
.kpi-card { display: flex; flex-direction: column; min-height: 128px; background: linear-gradient(180deg, rgba(13, 27, 45, 0.96), rgba(7, 15, 28, 0.96)); border: 1px solid rgba(45, 255, 243, 0.13); border-radius: var(--r-lg); padding: 1.05rem; box-shadow: 0 16px 42px rgba(0, 0, 0, 0.28); transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease; height: 100%; }
.kpi-card:hover { transform: translateY(-2px); border-color: rgba(45, 255, 243, 0.28); box-shadow: 0 22px 54px rgba(0, 0, 0, 0.34); }
.kpi-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.75rem; }
.kpi-icon { width: 40px; height: 40px; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center; background: rgba(39, 245, 238, 0.10); border: 1px solid rgba(39, 245, 238, 0.18); font-size: 1rem; flex: 0 0 40px; }
.kpi-label { margin-top: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.14em; font-size: 0.7rem; font-weight: 800; }
.kpi-value { margin-top: 0.4rem; color: var(--text); font-size: clamp(1.6rem, 2.2vw, 2.2rem); font-weight: 850; line-height: 1.02; }
.kpi-value.compact { font-size: clamp(1.25rem, 1.5vw, 1.55rem); line-height: 1.18; }
.kpi-note { margin-top: auto; padding-top: 0.4rem; color: var(--muted); font-size: 0.84rem; line-height: 1.45; }

.panel-card, .insight-card, .empty-card, .surface-card { padding: var(--pad-card); display: flex; flex-direction: column; }
.panel-card, .insight-card, .empty-card, .surface-card, .score-card { transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease; }
.panel-card:hover, .insight-card:hover, .empty-card:hover, .surface-card:hover, .score-card:hover { transform: translateY(-1px); border-color: rgba(45, 255, 243, 0.22); box-shadow: 0 18px 36px rgba(0, 0, 0, 0.20); }
.panel-card + .panel-card { margin-top: var(--gap); }
.panel-title { margin: 0 0 0.3rem; color: var(--text); font-size: 1.02rem; font-weight: 750; line-height: 1.25; }
.panel-subtitle { color: var(--muted); font-size: 0.86rem; margin-bottom: 0.85rem; line-height: 1.5; }
.panel-card > *:last-child, .surface-card > *:last-child, .insight-card > *:last-child { margin-bottom: 0; }
.about-stack { display: grid; gap: 1rem; margin-top: 1rem; }
.about-stack .panel-card,
.about-stack .surface-card { margin: 0; }
.section-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: var(--gap); }

.stTextInput div[data-baseweb="input"],
.stTextArea textarea,
.stFileUploader section,
.stSelectbox div[data-baseweb="select"],
.stMultiSelect div[data-baseweb="select"] { background: rgba(11, 23, 41, 0.88) !important; color: var(--text) !important; border: 1px solid rgba(45, 255, 243, 0.42) !important; border-radius: var(--r-md) !important; min-height: 48px; box-shadow: 0 0 0 1px rgba(45, 255, 243, 0.04), inset 0 0 0 1px rgba(45, 255, 243, 0.06) !important; }
.stFileUploader { margin-top: 1rem; }
.stFileUploader section { min-height: 70px !important; padding: 0.7rem 0.85rem !important; display: flex !important; align-items: center !important; }
.stFileUploader section > div { width: 100% !important; display: flex !important; align-items: center !important; gap: 1rem !important; flex-wrap: wrap !important; }
.stFileUploader button { min-height: 46px !important; border-radius: 12px !important; }
.stSelectbox div[data-baseweb="select"] { min-height: 54px !important; align-items: center !important; }
.stSelectbox div[data-baseweb="select"] > div { min-height: 52px !important; align-items: center !important; padding-left: 0.35rem !important; }
.stMultiSelect div[data-baseweb="select"] { min-height: 56px !important; align-items: center !important; overflow: hidden !important; }
.stMultiSelect div[data-baseweb="select"] > div { min-height: 54px !important; align-items: center !important; background: transparent !important; border: 0 !important; box-shadow: none !important; }
.stMultiSelect div[data-baseweb="select"] > div:first-child { padding-left: 0.45rem !important; }
.stTextInput { margin-bottom: 0.35rem; }
.stTextInput div[data-baseweb="input"] { width: 100% !important; height: 54px !important; align-items: center !important; }
.stTextInput input { box-sizing: border-box !important; width: 100% !important; height: 52px !important; line-height: 52px !important; padding: 0 1.4rem !important; border: 0 !important; box-shadow: none !important; background: transparent !important; overflow: hidden !important; text-overflow: clip !important; }
.stTextInput div[data-baseweb="input"]:focus-within,
.stSelectbox div[data-baseweb="select"]:focus-within,
.stMultiSelect div[data-baseweb="select"]:focus-within,
.stTextArea textarea:focus,
.stDateInput input:focus { border-color: rgba(45, 255, 243, 0.95) !important; box-shadow: 0 0 0 1px rgba(45, 255, 243, 0.75), 0 0 18px rgba(45, 255, 243, 0.16) !important; }
.stTextInput [data-testid="InputInstructions"] { display: none !important; }
.stSelectbox label p,
.stMultiSelect label p,
.stDateInput label p,
.stSelectbox [data-testid="stWidgetLabel"] p,
.stMultiSelect [data-testid="stWidgetLabel"] p,
.stDateInput [data-testid="stWidgetLabel"] p { color: #e8f2ff !important; font-weight: 720 !important; }
.stMultiSelect [data-baseweb="tag"] { background: linear-gradient(90deg, rgba(39, 245, 238, 0.34), rgba(109, 124, 255, 0.24)) !important; border: 1px solid rgba(45, 255, 243, 0.42) !important; border-radius: 8px !important; box-shadow: none !important; min-height: 36px !important; margin-top: 0 !important; margin-bottom: 0 !important; }
.stMultiSelect [data-baseweb="tag"] span,
.stMultiSelect [data-baseweb="tag"] div { color: #f4fbff !important; font-weight: 760 !important; }
.stMultiSelect [data-baseweb="tag"] svg { color: #eaffff !important; fill: #eaffff !important; }
.stSelectbox div[data-baseweb="select"] input,
.stMultiSelect div[data-baseweb="select"] input,
.stDateInput input { color: #eaf3ff !important; }
.stDateInput input { min-height: 54px !important; border: 1px solid rgba(45, 255, 243, 0.58) !important; border-radius: 14px !important; background: rgba(11, 23, 41, 0.88) !important; box-shadow: inset 0 0 0 1px rgba(45, 255, 243, 0.10) !important; padding: 0 1rem !important; }
.stTextInput input::placeholder,
.stTextArea textarea::placeholder { color: rgba(142, 167, 198, 0.72) !important; }
.stButton button,
.stDownloadButton button { background: linear-gradient(90deg, var(--accent), var(--accent-2)) !important; color: #04111f !important; border: 0 !important; border-radius: 14px !important; font-weight: 800 !important; transition: transform 140ms ease, box-shadow 140ms ease, filter 140ms ease; box-shadow: 0 12px 24px rgba(39, 245, 238, 0.15); }
.stButton { margin-top: 0; }
.stButton button:hover,
.stDownloadButton button:hover { transform: translateY(-1px); filter: brightness(1.03); }
.stButton button { min-height: 48px; }
.stDownloadButton button { min-height: 46px; }
[data-testid="stSidebar"] .stButton button { min-height: 42px !important; border-radius: 12px !important; font-size: 0.9rem !important; box-shadow: 0 10px 20px rgba(39, 245, 238, 0.12) !important; }
.stDataFrame, .stDataEditor { border-radius: var(--r-md); overflow: hidden; }
table { color: var(--text); }
.thin-divider { height: 1px; width: 100%; background: linear-gradient(90deg, transparent, rgba(45, 255, 243, 0.22), transparent); margin: 0.85rem 0; }
.scoreboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.7rem; align-items: stretch; }
.score-card { display: flex; flex-direction: column; background: rgba(11, 22, 40, 0.78); border: 1px solid rgba(45, 255, 243, 0.10); border-radius: var(--r-md); padding: 0.9rem 0.95rem; height: 100%; }
.score-label { color: var(--muted); font-size: 0.73rem; text-transform: uppercase; letter-spacing: 0.12em; font-weight: 800; }
.score-value { margin-top: 0.4rem; color: var(--text); font-size: 1.1rem; font-weight: 800; line-height: 1.15; }
.score-meta { margin-top: auto; padding-top: 0.25rem; color: var(--muted); font-size: 0.82rem; }

@media (max-width: 1180px) {
    .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .scoreboard { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .hero-metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}

@media (max-width: 760px) {
    .block-container { padding-top: 0.65rem; padding-left: 0.8rem; padding-right: 0.8rem; }
    .kpi-grid, .scoreboard, .hero-metrics { grid-template-columns: 1fr; }
    .hero-card, .panel-card, .insight-card, .empty-card, .surface-card { padding: 1rem; }
    .hero-stack { flex-direction: column; align-items: stretch; }
    .status-row { justify-content: flex-start; }
    [data-testid="stSidebar"] { position: fixed; inset: 0 auto 0 0; z-index: 1000; width: min(88vw, 320px) !important; min-width: min(88vw, 320px) !important; max-width: min(88vw, 320px) !important; box-shadow: 24px 0 48px rgba(0, 0, 0, 0.32); }
    [data-testid="stSidebar"][aria-expanded="false"] { display: none; }
    .stRadio [role="radiogroup"] > label { padding: 0.68rem 0.72rem; }
}
</style>
"""


def apply_theme() -> None:
    st.markdown(CYBER_CSS, unsafe_allow_html=True)


def format_percentage(value: float) -> str:
    return f"{value * 100:.1f}%"


def to_local_timestamp(value) -> pd.Timestamp:
    timestamp = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(timestamp):
        return pd.NaT
    return timestamp.tz_convert(LOCAL_TIMEZONE)


def format_display_time(value) -> str:
    timestamp = to_local_timestamp(value)
    if pd.isna(timestamp):
        return ""
    return f"{timestamp.strftime('%Y-%m-%d %H:%M')} {LOCAL_TIMEZONE_LABEL}"


def format_date_span(start_date, end_date) -> str:
    if start_date == end_date:
        return str(start_date)
    return f"{start_date}<br><span style='font-size:0.82em;color:#8da4c0;'>to</span><br>{end_date}"


def render_badge(label: str, tone: str = "") -> str:
    suffix = f" {tone}" if tone else ""
    return f'<span class="pill{suffix}">{label}</span>'


def render_hero(
    title: str,
    subtitle: str,
    badges: List[str] | None = None,
    actions: List[Dict[str, str]] | None = None,
    show_metrics: bool = True,
) -> None:
    badges = badges or [render_badge("AI Detection Active", "good")]
    badge_markup = "".join(f"<span>{badge}</span>" for badge in badges)
    metrics_html = ""
    if show_metrics:
        metrics_html = (
            '<div class="hero-metrics">'
            '<div class="hero-metric">'
            '<div class="hero-metric-label">Live scanning</div>'
            '<div class="hero-metric-value">AI URL analysis</div>'
            '<div class="hero-metric-note">Real-time phishing detection</div>'
            '</div>'
            '<div class="hero-metric">'
            '<div class="hero-metric-label">Risk scoring</div>'
            '<div class="hero-metric-value">Confidence driven</div>'
            '<div class="hero-metric-note">Threat intelligence output</div>'
            '</div>'
            '<div class="hero-metric">'
            '<div class="hero-metric-label">Enterprise view</div>'
            '<div class="hero-metric-value">Security analytics</div>'
            '<div class="hero-metric-note">Operational cyber insights</div>'
            '</div>'
            '</div>'
        )
    st.markdown(
        f"""
        <div class="hero-card">
            <div class="hero-stack">
                <div class="hero-copy">
                    <div class="eyebrow">Enterprise Cyber Threat Intelligence</div>
                    <h1 class="hero-title">{title}</h1>
                    <div class="hero-subtitle">{subtitle}</div>
                    <div class="hero-description">
                        PhishGuard AI analyzes suspicious URLs, detects phishing attacks, classifies malicious links, and delivers
                        confidence-based threat scoring for real-time cybersecurity decisions.
                    </div>
                </div>
                <div class="status-row">{badge_markup}</div>
            </div>
            {metrics_html}
        </div>
        """,
        unsafe_allow_html=True,
    )
    if actions:
        st.markdown('<div class="hero-action-grid">', unsafe_allow_html=True)
        action_columns = st.columns(len(actions))
        for column, action in zip(action_columns, actions):
            with column:
                if st.button(action["label"], use_container_width=True, key=action["key"]):
                    # Mark that a hero-driven navigation is pending so the main
                    # loop can safely map it to the radio widget before it's
                    # created. This prevents us from overwriting user-driven
                    # radio changes later.
                    st.session_state["active_section"] = action["target"]
                    st.session_state["hero_nav_pending"] = True
                    # Force an immediate second pass so the state set above is
                    # applied right away and navigation happens on one tap.
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


def render_section_header(title: str, subtitle: str = "", right: str = "", anchor_id: str | None = None) -> None:
    anchor_attr = f' id="{anchor_id}"' if anchor_id else ""
    st.markdown(
        f"""
        <div class="section-head"{anchor_attr}>
            <div>
                <div class="section-title">{title}</div>
                <div class="section-subtitle">{subtitle}</div>
            </div>
            <div>{right}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpi_grid(cards: List[Dict[str, str]]) -> None:
    if not cards:
        return
    columns = st.columns(len(cards))
    for column, card in zip(columns, cards):
        with column:
            value = str(card["value"])
            value_class = card.get("value_class", "")
            if card.get("label") == "Date Span":
                value_class = f"{value_class} compact".strip()
                dates = re.findall(r"\d{4}-\d{2}-\d{2}", value)
                if len(dates) >= 2:
                    value = dates[0] if dates[0] == dates[1] else format_date_span(dates[0], dates[1])
            card_html = (
                f'<div class="kpi-card">'
                f'<div class="kpi-top">'
                f'<div class="kpi-icon">{card.get("icon", "◉")}</div>'
                f'<div>{card.get("badge", "")}</div>'
                f'</div>'
                f'<div class="kpi-label">{card["label"]}</div>'
                f'<div class="kpi-value {value_class}">{value}</div>'
                f'<div class="kpi-note">{card.get("note", "")}</div>'
                f'</div>'
            )
            st.markdown(card_html, unsafe_allow_html=True)


def render_surface_card(title: str, subtitle: str = "") -> None:
    st.markdown(
        f"""
        <div class="surface-card">
          <div class="panel-title">{title}</div>
          <div class="panel-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def chart_layout(fig: go.Figure, *, height: int = 360, title: str | None = None, legend: str = "h") -> go.Figure:
    top_margin = 46 if title or fig.layout.title.text else 22
    fig.update_layout(
        template="plotly_dark",
        height=height,
        margin={"l": 22, "r": 22, "t": top_margin, "b": 22},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, Segoe UI, sans-serif", "color": "#eaf3ff"},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1} if legend == "h" else {"orientation": "v"},
    )
    if title:
        fig.update_layout(title={"text": title, "x": 0.02, "xanchor": "left"})
    elif fig.layout.title.text:
        fig.update_layout(title={"text": fig.layout.title.text, "x": 0.02, "xanchor": "left"})
    fig.update_xaxes(gridcolor="rgba(141,164,192,0.12)", zerolinecolor="rgba(141,164,192,0.12)", automargin=True)
    fig.update_yaxes(gridcolor="rgba(141,164,192,0.12)", zerolinecolor="rgba(141,164,192,0.12)", automargin=True)
    # Only update hoverlabel for trace types that support it. Indicators/gauges
    # don't accept `hoverlabel` and will raise a ValueError if set globally.
    hover_cfg = {"bgcolor": "#081321", "bordercolor": "rgba(45,255,243,0.18)", "font": {"color": "#eaf3ff"}}
    for tr in fig.data:
        ttype = getattr(tr, "type", "").lower()
        if ttype in {"scatter", "bar", "pie", "heatmap", "box", "violin", "histogram", "line"}:
            try:
                tr.update(hoverlabel=hover_cfg)
            except Exception:
                # If a specific trace doesn't accept hoverlabel, skip it.
                pass
    return fig


def dual_gauge(confidence: float, risk: float) -> go.Figure:
    """Render compact, aligned confidence and risk gauges side by side."""
    def _indicator(value: float, title: str, domain_x: list[float]) -> go.Indicator:
        return go.Indicator(
            mode="gauge+number",
            value=round(value * 100, 1),
            number={"suffix": "%", "font": {"size": 26, "color": "#eaf3ff"}},
            title={"text": title, "font": {"color": "#8da4c0", "size": 13}},
            domain={"x": domain_x, "y": [0, 1]},
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 1,
                    "tickcolor": "#8da4c0",
                    "tickfont": {"size": 10, "color": "#8da4c0"},
                },
                "bar": {"color": "#27f5ee", "thickness": 0.3},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 50], "color": "rgba(255,77,109,0.18)"},
                    {"range": [50, 75], "color": "rgba(245,158,11,0.16)"},
                    {"range": [75, 100], "color": "rgba(16,185,129,0.16)"},
                ],
            },
        )

    fig = go.Figure()
    fig.add_trace(_indicator(confidence, "Model Confidence", [0.0, 0.46]))
    fig.add_trace(_indicator(risk, "Risk Meter", [0.54, 1.0]))
    fig.update_layout(
        height=250,
        margin={"l": 20, "r": 20, "t": 46, "b": 12},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, Segoe UI, sans-serif", "color": "#eaf3ff"},
    )
    return fig


def severity_badge(threat_level: str) -> str:
    level = threat_level.lower()
    tone = "good" if level == "safe" else "warn" if level == "low" else "danger" if level in {"high", "critical"} else ""
    return render_badge(threat_level, tone)


def set_active_page(page_name: str) -> None:
    st.session_state["active_section"] = page_name


def load_demo_url() -> None:
    demo_url = st.session_state.get("phishguard-demo-url", "")
    if demo_url:
        st.session_state["phishguard-scan-url"] = demo_url


def render_sidebar() -> str:
    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-shell">
              <div class="sidebar-brand">
                <div class="brand-mark">🛡️</div>
                <div>
                  <div class="brand-kicker">PhishGuard AI</div>
                  <div class="brand-title">Threat Intelligence Console</div>
                </div>
              </div>
              <div class="brand-subtitle">AI-powered phishing URL detection and cyber threat intelligence.</div>
              <div class="brand-description"><strong>Real-time URL scanning</strong>, malicious link classification, and confidence-based threat scoring for enterprise security teams.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height:0.85rem'></div>", unsafe_allow_html=True)
        st.markdown('<div class="nav-badge">● Live monitoring enabled</div>', unsafe_allow_html=True)
        st.markdown('<div class="nav-header">Navigation</div>', unsafe_allow_html=True)
        nav_labels = {
            item["title"]: f'{item["icon"]}  {item["title"]}\n{item["subtitle"]}'
            for item in NAV_ITEMS
        }
        selected = st.radio(
            "Navigate",
            [item["title"] for item in NAV_ITEMS],
            format_func=lambda value: nav_labels[value],
            label_visibility="collapsed",
            key="phishguard-nav",
        )
        st.markdown("<div class='thin-divider'></div>", unsafe_allow_html=True)
        st.markdown('<div class="nav-hint">Reload latest scans and model status.</div>', unsafe_allow_html=True)
        if st.button("Refresh data", use_container_width=True):
            st.rerun()
    return selected


class DashboardClient:
    def __init__(self) -> None:
        self.api_base_url = os.getenv("API_BASE_URL", "").rstrip("/")

    def _has_api(self) -> bool:
        return bool(self.api_base_url)

    def _api_url(self, path: str) -> str:
        return f"{self.api_base_url}{path}"

    def _request_json(self, method: str, path: str, **kwargs):
        if not self._has_api():
            return None
        try:
            response = requests.request(method, self._api_url(path), timeout=15, **kwargs)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None

    def health(self) -> Dict:
        remote = self._request_json("GET", "/health")
        if remote:
            return remote
        data = model_service.get_health_snapshot()
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        return data

    def model_info(self) -> Dict:
        remote = self._request_json("GET", "/model-info")
        if remote:
            return remote
        return model_service.get_model_info()

    def predict_url(self, url: str) -> Dict:
        remote = self._request_json("POST", "/predict", json={"url": url})
        if remote:
            prediction_store.append(remote)
            return remote
        prediction = model_service.predict(url=url, source="dashboard")
        prediction_store.append(prediction)
        return prediction

    def predict_batch(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        if self._has_api():
            csv_bytes = dataframe.to_csv(index=False).encode("utf-8")
            remote = self._request_json(
                "POST",
                "/batch-predict",
                files={"file": ("batch.csv", io.BytesIO(csv_bytes), "text/csv")},
            )
            if isinstance(remote, dict):
                records = remote.get("results", [])
                for record in records:
                    prediction_store.append(record)
                return pd.DataFrame(records)
        predictions = model_service.predict_dataframe(dataframe, source="dashboard")
        for record in predictions.to_dict(orient="records"):
            prediction_store.append(record)
        return predictions

    def recent_history(self, limit: int = 200) -> List[Dict]:
        remote = self._request_json("GET", f"/history?limit={limit}")
        if isinstance(remote, list):
            return remote
        return prediction_store.load(limit=limit)

    def threat_stats(self) -> Dict:
        remote = self._request_json("GET", "/threat-stats")
        if isinstance(remote, dict):
            return remote
        history = self.recent_history(limit=500)
        return build_threat_statistics(history)

    def feature_importance(self) -> pd.DataFrame:
        snapshot = model_service._snapshot
        model = snapshot.model
        feature_names = snapshot.feature_names
        if model is None:
            return pd.DataFrame(columns=["feature", "importance"])
        if hasattr(model, "feature_importances_"):
            importances = getattr(model, "feature_importances_")
        elif hasattr(model, "coef_"):
            importances = abs(getattr(model, "coef_")).ravel()
        else:
            importances = [0.0] * len(feature_names)
        return pd.DataFrame({"feature": feature_names, "importance": importances}).sort_values(by="importance", ascending=False)


client = DashboardClient()


def render_executive() -> None:
    stats = client.threat_stats()
    info = client.model_info()
    health = client.health()
    active_section = st.session_state.get("active_section")
    history_backend = health.get("history_backend", "file")
    render_hero(
        "PhishGuard AI",
        "AI-Powered Phishing URL Detection & Threat Intelligence Platform",
        badges=[
            render_badge("Live telemetry", "good"),
            render_badge("URL threat analysis", "warn"),
            render_badge(health.get("status", "Healthy"), "good" if health.get("status") == "healthy" else "warn"),
            render_badge("Durable history" if history_backend == "mongo" else "Local history", "good" if history_backend == "mongo" else "warn"),
        ],
        actions=[
            {"label": "Scan Suspicious URL", "target": "scanner", "key": "home-open-scanner"},
            {"label": "Open Analytics", "target": "analytics", "key": "home-open-analytics"},
        ],
    )
    render_kpi_grid(
        [
            {"icon": "🛡️", "label": "Total Scans", "value": f"{stats['total_predictions']}", "note": "All tracked detections", "badge": render_badge("Realtime", "good")},
            {"icon": "🚨", "label": "Phishing Flags", "value": f"{stats['phishing_count']}", "note": "Potential threats", "badge": render_badge("Alerting", "danger")},
            {"icon": "✅", "label": "Legitimate URLs", "value": f"{stats['legitimate_count']}", "note": "Approved traffic", "badge": render_badge("Trusted", "good")},
            {"icon": "📊", "label": "Model F1", "value": f"{info.get('metrics', {}).get('f1_score', 0):.3f}", "note": "Latest artifact snapshot", "badge": render_badge("Performance", "warn")},
        ]
    )
    if history_backend != "mongo":
        st.markdown(
            "<div class='empty-card'>Prediction history is using local file storage. Set <strong>MONGO_DB_URL</strong> for durable shared history, or mount <strong>PREDICTION_HISTORY_FILE</strong> on persistent storage.</div>",
            unsafe_allow_html=True,
        )
    st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

    if active_section == "scanner":
        render_real_time(embedded=True)
        return
    if active_section == "analytics":
        render_threat_analytics(embedded=True)
        return

    left, right = st.columns([1.08, 0.92], vertical_alignment="top")
    with left:
        render_section_header("Threat Mix", "Distribution of monitored outcomes across the current data window.")
        threat_levels = stats["by_threat_level"]
        if threat_levels:
            pie = px.pie(
                values=list(threat_levels.values()),
                names=list(threat_levels.keys()),
                hole=0.62,
                color_discrete_sequence=["#27f5ee", "#8b5cf6", "#f59e0b", "#ff4d6d", "#10b981"],
            )
            pie.update_traces(textposition="inside", textinfo="percent+label", marker=dict(line=dict(color="#081321", width=2)))
            st.plotly_chart(chart_layout(pie, height=360, legend="v"), use_container_width=True)
        else:
            st.markdown('<div class="empty-card">No threat data available yet.</div>', unsafe_allow_html=True)
    with right:
        render_section_header("Risk Categories", "Severity clusters that surface the highest-priority detections.")
        risk_levels = stats["by_risk_category"]
        if risk_levels:
            bar = px.bar(
                x=list(risk_levels.keys()),
                y=list(risk_levels.values()),
                color=list(risk_levels.keys()),
                color_discrete_sequence=["#27f5ee", "#8b5cf6", "#f59e0b", "#ff4d6d"],
            )
            bar.update_traces(marker_line_color="#081321", marker_line_width=1.2)
            st.plotly_chart(chart_layout(bar, height=360), use_container_width=True)
        else:
            st.markdown('<div class="empty-card">No risk breakdown available yet.</div>', unsafe_allow_html=True)
    trend = stats.get("trend", [])
    if trend:
        render_section_header("Confidence Trend", "Time-series view of recent model confidence scores.")
        trend_fig = go.Figure()
        trend_fig.add_trace(
            go.Scatter(
                x=[item["timestamp"] for item in trend],
                y=[item["confidence_score"] * 100 for item in trend],
                mode="lines+markers",
                line={"color": "#27f5ee", "width": 3},
                marker={"size": 7, "color": "#8b5cf6"},
                name="Confidence",
            )
        )
        trend_fig.update_xaxes(title_text="Timestamp")
        trend_fig.update_yaxes(title_text="Confidence %", range=[0, 100])
        st.plotly_chart(chart_layout(trend_fig, height=320), use_container_width=True)


def render_real_time_legacy(embedded: bool = False) -> None:
    if not embedded:
        render_hero(
            "Real-Time URL Detection",
            "Scan suspicious URLs instantly and surface a structured threat assessment with confidence scoring.",
            badges=[render_badge("Low latency", "good"), render_badge("Auto triage", "warn")],
            show_metrics=False,
        )
    else:
        render_section_header("Real-Time URL Detection", "Scan suspicious URLs instantly inside the current dashboard.", anchor_id="url-scanner")
    left, right = st.columns([1.05, 0.95], vertical_alignment="top")
    with left:
        render_section_header("URL Analyst", "Paste a target URL and run an immediate phishing assessment.", anchor_id="url-scanner")
        st.markdown(
            "<div class='panel-card'><div class='panel-title'>Demo URLs</div><div class='panel-subtitle'>Pick a sample phishing URL or paste your own to simulate an enterprise triage workflow.</div></div>",
            unsafe_allow_html=True,
        )
        st.selectbox(
            "Load a sample URL",
            ["Use a sample URL"] + SAMPLE_PHISHING_URLS,
            key="phishguard-demo-url",
            on_change=load_demo_url,
        )
        st.markdown("<div style='height:0.65rem'></div>", unsafe_allow_html=True)
        url = st.text_input(
            "Target URL",
            placeholder="https://malicious-example.com/login",
            label_visibility="visible",
            key="phishguard-scan-url",
        )
        st.markdown("<div style='height:0.65rem'></div>", unsafe_allow_html=True)
        analyze = st.button("Analyze URL", use_container_width=True, key="phishguard-analyze-url")
    with right:
        render_section_header("Live Result", "Returned detection state and risk summary.")
        result_placeholder = st.empty()
        if analyze:
            if not url.strip():
                with result_placeholder.container():
                    st.markdown('<div class="empty-card">Paste a URL or load a sample to begin the scan.</div>', unsafe_allow_html=True)
                return

            with result_placeholder.container():
                loading_panel = st.empty()
                progress = st.progress(0, text="Initializing analysis")
                with st.status("Running security analysis", expanded=True) as status:
                    loading_panel.markdown(
                        "<div class='panel-card'><div class='panel-title'>Scanning in progress</div><div class='panel-subtitle'>Evaluating URL structure, host patterns, and phishing signals.</div></div>",
                        unsafe_allow_html=True,
                    )
                    status.write("Normalizing URL and checking host reputation…")
                    time.sleep(0.12)
                    progress.progress(33, text="Checking phishing indicators")
                    status.write("Inspecting credential harvesting and redirect patterns…")
                    time.sleep(0.12)
                    progress.progress(66, text="Generating AI verdict")
                    try:
                        result = client.predict_url(url)
                    except RuntimeError as exc:
                        status.update(label="Model unavailable", state="error")
                        st.error(str(exc))
                        st.info(
                            "If this is Streamlit Cloud, confirm that the latest commit includes "
                            "final_model/model.pkl and final_model/preprocessor.pkl, then reboot the app."
                        )
                        return
                    time.sleep(0.12)
                    progress.progress(100, text="Scan complete")
                    status.update(label="Analysis complete", state="complete")

                loading_panel.empty()
                progress.empty()

                threat_status = "Threat Detected" if result.get("prediction", "").lower() != "legitimate" else "No Threat Detected"
                ai_verdict = "Likely phishing attempt" if threat_status == "Threat Detected" else "Likely safe URL"
                confidence_value = float(result.get("confidence_score", 0.0))
                risk_level = result.get("risk_category", "Unknown")
                reason_codes = result.get("reason_codes", [])
                heuristic_score = float(result.get("heuristic_score", 0.0) or 0.0)
                risk_score = float(result.get("risk_score", heuristic_score) or heuristic_score)
                triggered_indicators = result.get("triggered_indicators", [])
                suspicious_keywords = result.get("suspicious_keywords", [])
                explanation = result.get("explanation", "")
                risk_breakdown = result.get("risk_score_breakdown", {}) or {}
                contribution_breakdown = result.get("feature_contribution_breakdown", []) or []
                text_evidence = result.get("text_evidence", {}) or {}

                st.markdown(
                    f"""
                    <div class="panel-card">
                        <div class="scoreboard">
                            <div class="score-card">
                                <div class="score-label">Threat Status</div>
                                <div class="score-value">{threat_status}</div>
                                <div class="score-meta">Detection state</div>
                            </div>
                            <div class="score-card">
                                <div class="score-label">Confidence Score</div>
                                <div class="score-value">{format_percentage(confidence_value)}</div>
                                <div class="score-meta">Model certainty</div>
                            </div>
                            <div class="score-card">
                                <div class="score-label">Risk Level</div>
                                <div class="score-value">{risk_level}</div>
                                <div class="score-meta">Policy triage bucket</div>
                            </div>
                            <div class="score-card">
                                <div class="score-label">AI Verdict</div>
                                <div class="score-value">{ai_verdict}</div>
                                <div class="score-meta">Assistant conclusion</div>
                            </div>
                            <div class="score-card">
                                <div class="score-label">Risk Meter</div>
                                <div class="score-value">{format_percentage(risk_score)}</div>
                                <div class="score-meta">Hybrid risk score</div>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.plotly_chart(
                    dual_gauge(confidence_value, risk_score),
                    use_container_width=True,
                    config={"displayModeBar": False, "staticPlot": True},
                )
                st.markdown(
                    f"<div class='analysis-time'><span class='pill good'>Analyzed at {format_display_time(result.get('timestamp', ''))}</span></div>",
                    unsafe_allow_html=True,
                )
                st.success(f"The platform classified the URL as {result.get('prediction', 'Unknown').lower()} with {format_percentage(confidence_value)} confidence.")
                if triggered_indicators:
                    st.markdown(
                        "<div class='panel-card'><div class='panel-title'>Triggered Indicators</div><div class='panel-subtitle'>" +
                        " ".join(f'<span class="pill danger">{indicator}</span>' for indicator in triggered_indicators) +
                        "</div></div>",
                        unsafe_allow_html=True,
                    )
                if suspicious_keywords:
                    st.markdown(
                        "<div class='panel-card'><div class='panel-title'>Suspicious Keywords Found</div><div class='panel-subtitle'>" +
                        ", ".join(suspicious_keywords) +
                        "</div></div>",
                        unsafe_allow_html=True,
                    )
                if explanation:
                    st.markdown(
                        f"<div class='panel-card'><div class='panel-title'>Explanation Panel</div><div class='panel-subtitle'>{explanation}</div></div>",
                        unsafe_allow_html=True,
                    )
                if risk_breakdown:
                    breakdown_df = pd.DataFrame(
                        [{"indicator": key, "score": value} for key, value in risk_breakdown.items()]
                    ).sort_values(by="score", ascending=False)
                    if not breakdown_df.empty:
                        fig = px.bar(
                            breakdown_df.head(10),
                            x="score",
                            y="indicator",
                            orientation="h",
                            title="Risk Score Breakdown",
                            color="score",
                            color_continuous_scale=[[0, "#27f5ee"], [1, "#8b5cf6"]],
                        )
                        fig.update_layout(coloraxis_showscale=False)
                        max_score = float(breakdown_df["score"].max() or 1)
                        fig.update_xaxes(range=[0, max_score * 1.12])
                        fig.update_layout(bargap=0.28)
                        st.plotly_chart(chart_layout(fig, height=360), use_container_width=True)
                if contribution_breakdown:
                    contribution_df = pd.DataFrame(contribution_breakdown)
                    if not contribution_df.empty and "impact" in contribution_df.columns:
                        fig = px.bar(
                            contribution_df.head(8),
                            x="impact",
                            y="feature",
                            orientation="h",
                            title="Feature Contribution Breakdown",
                            color="impact",
                            color_continuous_scale=[[0, "#27f5ee"], [1, "#ff4d6d"]],
                        )
                        fig.update_layout(coloraxis_showscale=False)
                        max_impact = float(contribution_df["impact"].max() or 1)
                        fig.update_xaxes(range=[0, max_impact * 1.12])
                        fig.update_layout(bargap=0.28)
                        st.plotly_chart(chart_layout(fig, height=340), use_container_width=True)
                if text_evidence:
                    st.markdown(
                        f"<div class='panel-card'><div class='panel-title'>TF-IDF Evidence</div><div class='panel-subtitle'>Malicious similarity: {text_evidence.get('malicious_similarity', 0.0):.3f} | Benign similarity: {text_evidence.get('benign_similarity', 0.0):.3f}</div><div class='panel-subtitle'>Top n-grams: {', '.join(text_evidence.get('top_ngrams', [])) or 'None'}</div></div>",
                        unsafe_allow_html=True,
                    )
                if reason_codes:
                    pretty_reasons = ", ".join(reason_codes)
                    st.markdown(
                        f"<div class='panel-card'><div class='panel-title'>Why it was flagged</div><div class='panel-subtitle'>{pretty_reasons}</div><div class='panel-subtitle'>Heuristic score: {heuristic_score:.2f}</div></div>",
                        unsafe_allow_html=True,
                    )
            return

        with result_placeholder.container():
            st.markdown(
                "<div class='empty-card'>Scan a suspicious URL to view threat status, confidence score, risk level, and AI verdict.</div>",
                unsafe_allow_html=True,
            )


def render_real_time(embedded: bool = False) -> None:
    if not embedded:
        render_hero(
            "Real-Time URL Detection",
            "Scan suspicious URLs instantly and surface a structured threat assessment with confidence scoring.",
            badges=[render_badge("Low latency", "good"), render_badge("Auto triage", "warn")],
            show_metrics=False,
        )
    else:
        render_section_header("Real-Time URL Detection", "Scan suspicious URLs instantly inside the current dashboard.", anchor_id="url-scanner")

    # ---- Input row: analyst form on the left, quick guidance on the right ----
    left, right = st.columns([1.1, 0.9], vertical_alignment="top")
    with left:
        render_section_header("URL Analyst", "Paste a target URL and run an immediate phishing assessment.", anchor_id="url-scanner")
        st.selectbox(
            "Load a sample URL",
            ["Use a sample URL"] + SAMPLE_PHISHING_URLS,
            key="phishguard-demo-url",
            on_change=load_demo_url,
        )
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        url = st.text_input(
            "Target URL",
            placeholder="https://malicious-example.com/login",
            label_visibility="visible",
            key="phishguard-scan-url",
        )
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        analyze = st.button("Analyze URL", use_container_width=True, key="phishguard-analyze-url")
    with right:
        render_section_header("How scanning works", "Simulated enterprise triage workflow.")
        st.markdown(
            "<div class='panel-card'><div class='panel-title'>Analysis pipeline</div>"
            "<div class='panel-subtitle'>1. Normalize URL &amp; check host reputation.<br>"
            "2. Inspect phishing indicators &amp; keywords.<br>"
            "3. Score with the ML model and generate an AI verdict.</div></div>",
            unsafe_allow_html=True,
        )

    # ---- Results render FULL WIDTH below the input row ----
    st.markdown("<div class='thin-divider'></div>", unsafe_allow_html=True)
    render_section_header("Live Result", "Returned detection state and risk summary.")

    if not analyze:
        st.markdown(
            "<div class='empty-card'>Scan a suspicious URL to view threat status, confidence score, risk level, and AI verdict.</div>",
            unsafe_allow_html=True,
        )
        return

    if not url.strip():
        st.markdown('<div class="empty-card">Paste a URL or load a sample to begin the scan.</div>', unsafe_allow_html=True)
        return

    progress = st.progress(0, text="Initializing analysis")
    with st.status("Running security analysis", expanded=True) as status:
        status.write("Normalizing URL and checking host reputationâ€¦")
        time.sleep(0.12)
        progress.progress(33, text="Checking phishing indicators")
        status.write("Inspecting credential harvesting and redirect patternsâ€¦")
        time.sleep(0.12)
        progress.progress(66, text="Generating AI verdict")
        try:
            result = client.predict_url(url)
        except RuntimeError as exc:
            status.update(label="Model unavailable", state="error")
            st.error(str(exc))
            st.info(
                "If this is Streamlit Cloud, confirm that the latest commit includes "
                "final_model/model.pkl and final_model/preprocessor.pkl, then reboot the app."
            )
            return
        time.sleep(0.12)
        progress.progress(100, text="Scan complete")
        status.update(label="Analysis complete", state="complete")
    progress.empty()

    threat_status = "Threat Detected" if result.get("prediction", "").lower() != "legitimate" else "No Threat Detected"
    ai_verdict = "Likely phishing attempt" if threat_status == "Threat Detected" else "Likely safe URL"
    confidence_value = float(result.get("confidence_score", 0.0))
    risk_level = result.get("risk_category", "Unknown")
    reason_codes = result.get("reason_codes", [])
    heuristic_score = float(result.get("heuristic_score", 0.0) or 0.0)
    risk_score = float(result.get("risk_score", heuristic_score) or heuristic_score)
    triggered_indicators = result.get("triggered_indicators", [])
    suspicious_keywords = result.get("suspicious_keywords", [])
    explanation = result.get("explanation", "")
    risk_breakdown = result.get("risk_score_breakdown", {}) or {}
    contribution_breakdown = result.get("feature_contribution_breakdown", []) or []
    text_evidence = result.get("text_evidence", {}) or {}

    # Scoreboard â€” full width (auto-fits 5 cards across the page)
    st.markdown(
        f"""
        <div class="panel-card">
            <div class="scoreboard">
                <div class="score-card"><div class="score-label">Threat Status</div><div class="score-value">{threat_status}</div><div class="score-meta">Detection state</div></div>
                <div class="score-card"><div class="score-label">Confidence Score</div><div class="score-value">{format_percentage(confidence_value)}</div><div class="score-meta">Model certainty</div></div>
                <div class="score-card"><div class="score-label">Risk Level</div><div class="score-value">{risk_level}</div><div class="score-meta">Policy triage bucket</div></div>
                <div class="score-card"><div class="score-label">AI Verdict</div><div class="score-value">{ai_verdict}</div><div class="score-meta">Assistant conclusion</div></div>
                <div class="score-card"><div class="score-label">Risk Meter</div><div class="score-value">{format_percentage(risk_score)}</div><div class="score-meta">Hybrid risk score</div></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.plotly_chart(
        dual_gauge(confidence_value, risk_score),
        use_container_width=True,
        config={"displayModeBar": False, "staticPlot": True},
    )
    st.markdown(
        f"<div class='analysis-time'><span class='pill good'>Analyzed at {format_display_time(result.get('timestamp', ''))}</span></div>",
        unsafe_allow_html=True,
    )
    st.success(f"The platform classified the URL as {result.get('prediction', 'Unknown').lower()} with {format_percentage(confidence_value)} confidence.")

    # Indicators / keywords / explanation â€” two aligned columns
    info_left, info_right = st.columns(2, vertical_alignment="top")
    with info_left:
        if triggered_indicators:
            st.markdown(
                "<div class='panel-card'><div class='panel-title'>Triggered Indicators</div><div class='panel-subtitle'>" +
                " ".join(f'<span class="pill danger">{indicator}</span>' for indicator in triggered_indicators) +
                "</div></div>",
                unsafe_allow_html=True,
            )
        if suspicious_keywords:
            st.markdown(
                "<div class='panel-card'><div class='panel-title'>Suspicious Keywords Found</div><div class='panel-subtitle'>" +
                ", ".join(suspicious_keywords) +
                "</div></div>",
                unsafe_allow_html=True,
            )
    with info_right:
        if explanation:
            st.markdown(
                f"<div class='panel-card'><div class='panel-title'>Explanation Panel</div><div class='panel-subtitle'>{explanation}</div></div>",
                unsafe_allow_html=True,
            )
        if text_evidence:
            st.markdown(
                f"<div class='panel-card'><div class='panel-title'>TF-IDF Evidence</div><div class='panel-subtitle'>Malicious similarity: {text_evidence.get('malicious_similarity', 0.0):.3f} | Benign similarity: {text_evidence.get('benign_similarity', 0.0):.3f}</div><div class='panel-subtitle'>Top n-grams: {', '.join(text_evidence.get('top_ngrams', [])) or 'None'}</div></div>",
                unsafe_allow_html=True,
            )

    # Bar charts â€” side by side, filling the full width
    chart_left, chart_right = st.columns(2, vertical_alignment="top")
    with chart_left:
        if risk_breakdown:
            breakdown_df = pd.DataFrame(
                [{"indicator": key, "score": value} for key, value in risk_breakdown.items()]
            ).sort_values(by="score", ascending=False)
            if not breakdown_df.empty:
                fig = px.bar(
                    breakdown_df.head(10),
                    x="score", y="indicator", orientation="h",
                    title="Risk Score Breakdown",
                    color="score",
                    color_continuous_scale=[[0, "#27f5ee"], [1, "#8b5cf6"]],
                )
                fig.update_layout(coloraxis_showscale=False, bargap=0.28)
                fig.update_xaxes(range=[0, float(breakdown_df["score"].max() or 1) * 1.12])
                st.plotly_chart(chart_layout(fig, height=360), use_container_width=True)
    with chart_right:
        if contribution_breakdown:
            contribution_df = pd.DataFrame(contribution_breakdown)
            if not contribution_df.empty and "impact" in contribution_df.columns:
                fig = px.bar(
                    contribution_df.head(8),
                    x="impact", y="feature", orientation="h",
                    title="Feature Contribution Breakdown",
                    color="impact",
                    color_continuous_scale=[[0, "#27f5ee"], [1, "#ff4d6d"]],
                )
                fig.update_layout(coloraxis_showscale=False, bargap=0.28)
                fig.update_xaxes(range=[0, float(contribution_df["impact"].max() or 1) * 1.12])
                st.plotly_chart(chart_layout(fig, height=360), use_container_width=True)

    if reason_codes:
        pretty_reasons = ", ".join(reason_codes)
        st.markdown(
            f"<div class='panel-card'><div class='panel-title'>Why it was flagged</div><div class='panel-subtitle'>{pretty_reasons}</div><div class='panel-subtitle'>Heuristic score: {heuristic_score:.2f}</div></div>",
            unsafe_allow_html=True,
        )
def render_threat_analytics(embedded: bool = False) -> None:
    if not embedded:
        render_hero(
            "Threat Analytics",
            "Track detection trends, threat concentrations, and risk posture over time with operator-friendly filters.",
            badges=[render_badge("Historical view", "good"), render_badge("Trend analysis", "warn")],
            show_metrics=False,
        )
    render_section_header("Threat Analytics", "Historical detections and risk clusters across the collected dataset.", anchor_id="threat-analytics")
    history = client.recent_history(limit=300)
    if not history:
        st.markdown('<div class="empty-card">No prediction history available yet.</div>', unsafe_allow_html=True)
        return
    df = pd.DataFrame(history)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True).dt.tz_convert(LOCAL_TIMEZONE)
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        st.markdown('<div class="empty-card">Prediction history exists, but no valid timestamps were found.</div>', unsafe_allow_html=True)
        return
    filters = st.columns(3)
    with filters[0]:
        prediction_filter = st.multiselect("Prediction", sorted(df["prediction"].dropna().unique().tolist()), default=sorted(df["prediction"].dropna().unique().tolist()))
    with filters[1]:
        threat_filter = st.multiselect("Threat level", sorted(df["threat_level"].dropna().unique().tolist()), default=sorted(df["threat_level"].dropna().unique().tolist()))
    with filters[2]:
        date_floor = df["timestamp"].dt.date.min()
        date_ceiling = df["timestamp"].dt.date.max()
        date_range = st.date_input("Date range", value=(date_floor, date_ceiling), format="YYYY-MM-DD")
    start_date, end_date = (date_range if isinstance(date_range, tuple) and len(date_range) == 2 else (date_floor, date_ceiling))
    filtered = df[
        df["prediction"].isin(prediction_filter)
        & df["threat_level"].isin(threat_filter)
        & (df["timestamp"].dt.date >= start_date)
        & (df["timestamp"].dt.date <= end_date)
    ]
    render_kpi_grid(
        [
            {"icon": "📦", "label": "Visible Events", "value": f"{len(filtered)}", "note": "After filters", "badge": render_badge("Filtered", "good")},
            {"icon": "🔎", "label": "Unique Threats", "value": f"{filtered['threat_level'].nunique()}", "note": "Threat tiers represented", "badge": render_badge("Coverage", "warn")},
            {"icon": "🕒", "label": "Date Span", "value": f"{start_date} → {end_date}", "note": "Analysis window", "badge": render_badge("Window", "good")},
            {"icon": "🧬", "label": "Confidence Avg", "value": f"{filtered['confidence_score'].mean() * 100:.1f}%", "note": "Mean model confidence", "badge": render_badge("Model", "good")},
        ]
    )
    if filtered.empty:
        st.markdown('<div class="empty-card">No rows match the selected filters.</div>', unsafe_allow_html=True)
        return
    col1, col2 = st.columns(2, vertical_alignment="top")
    with col1:
        by_prediction = px.pie(filtered, names="prediction", title="Detection Split", hole=0.55, color_discrete_sequence=["#27f5ee", "#8b5cf6"])
        by_prediction.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(chart_layout(by_prediction, height=360, legend="v"), use_container_width=True)
    with col2:
        by_threat = px.histogram(filtered, x="threat_level", color="prediction", title="Threat Distribution", barmode="group", color_discrete_sequence=["#27f5ee", "#8b5cf6"])
        st.plotly_chart(chart_layout(by_threat, height=360), use_container_width=True)
    daily = filtered.assign(date=filtered["timestamp"].dt.date).groupby(["date", "prediction"]).size().reset_index(name="count")
    trend = px.line(daily, x="date", y="count", color="prediction", markers=True, title="Daily Detection Trend", color_discrete_sequence=["#27f5ee", "#8b5cf6"])
    st.plotly_chart(chart_layout(trend, height=340), use_container_width=True)
    render_section_header("Recent Analysis Feed", f"Latest 15 records from {len(filtered)} filtered events.")
    display_cols = [col for col in ["timestamp", "prediction", "threat_level", "risk_category", "confidence_score", "url"] if col in filtered.columns]
    recent_display = filtered.sort_values("timestamp", ascending=False).head(15)[display_cols].copy()
    if "timestamp" in recent_display.columns:
        recent_display["timestamp"] = recent_display["timestamp"].apply(format_display_time)
        recent_display = recent_display.rename(columns={"timestamp": "date_time"})
    st.dataframe(recent_display, use_container_width=True, hide_index=True)


def render_batch_prediction() -> None:
    render_hero(
        "Batch Prediction",
        "Upload CSV files for large-scale scanning and export the results with a production-ready workflow.",
        badges=[render_badge("Bulk scan", "good"), render_badge("CSV export", "warn")],
        show_metrics=False,
    )
    uploader_col, notes_col = st.columns([1.1, 0.9], vertical_alignment="top")
    with uploader_col:
        st.markdown('<div class="panel-card"><div class="panel-title">Batch Intake</div><div class="panel-subtitle">Drop a CSV file and preview the dataset before analysis.</div></div>', unsafe_allow_html=True)
        uploaded = st.file_uploader("CSV file", type=["csv"], label_visibility="collapsed")
    with notes_col:
        st.markdown(
            """
            <div class="panel-card">
              <div class="panel-title">Operational Notes</div>
              <div class="panel-subtitle">Use standardized column names when possible. The platform will preserve your source fields and append prediction metadata.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    if not uploaded:
        st.markdown('<div class="empty-card">Upload a CSV to begin batch analysis.</div>', unsafe_allow_html=True)
        return
    dataframe = pd.read_csv(uploaded)
    render_section_header("Dataset Preview", f"{len(dataframe)} rows and {len(dataframe.columns)} columns detected.")
    st.dataframe(dataframe.head(10), use_container_width=True, hide_index=True)
    if st.button("Run Batch Scan", use_container_width=True):
        with st.status("Processing batch scan", expanded=True) as status:
            status.write("Validating source columns…")
            status.write("Scoring records against the loaded model…")
            predictions = client.predict_batch(dataframe)
            status.update(label="Batch scan complete", state="complete")
        st.success(f"Scanned {len(predictions)} records.")
        st.dataframe(predictions, use_container_width=True, hide_index=True)
        st.download_button(
            "Download Results CSV",
            data=predictions.to_csv(index=False).encode("utf-8"),
            file_name="phishing_batch_results.csv",
            mime="text/csv",
            use_container_width=True,
        )


def render_model_intelligence() -> None:
    render_hero(
        "Model Intelligence",
        "Inspect model quality, evaluation metrics, and feature signals powering the detector.",
        badges=[render_badge("Model quality", "good"), render_badge("Explainability", "warn")],
        show_metrics=False,
    )
    info = client.model_info()
    metrics = info.get("metrics", {})
    render_kpi_grid(
        [
            {"icon": "🎯", "label": "Accuracy", "value": f"{metrics.get('accuracy', 0.0):.3f}", "note": "Overall classification quality", "badge": render_badge("Core", "good")},
            {"icon": "🧮", "label": "Precision", "value": f"{metrics.get('precision', 0.0):.3f}", "note": "False positive control", "badge": render_badge("Precision", "warn")},
            {"icon": "📡", "label": "Recall", "value": f"{metrics.get('recall', 0.0):.3f}", "note": "Threat capture rate", "badge": render_badge("Recall", "good")},
            {"icon": "🏁", "label": "F1 Score", "value": f"{metrics.get('f1_score', 0.0):.3f}", "note": "Balanced score", "badge": render_badge("Benchmark", "good")},
        ]
    )
    top, bottom = st.columns([1, 1], vertical_alignment="top")
    with top:
        cm = go.Figure(
            data=go.Heatmap(
                z=[
                    [metrics.get("true_negative", 0), metrics.get("false_positive", 0)],
                    [metrics.get("false_negative", 0), metrics.get("true_positive", 0)],
                ],
                x=["Predicted Safe", "Predicted Phishing"],
                y=["Actual Safe", "Actual Phishing"],
                colorscale=[[0, "#07111f"], [0.35, "#27f5ee"], [1, "#8b5cf6"]],
                hovertemplate="%{z}<extra></extra>",
            )
        )
        cm.update_coloraxes(colorbar_thickness=12)
        st.plotly_chart(chart_layout(cm, height=360, title="Confusion Matrix"), use_container_width=True)
    with bottom:
        feature_df = client.feature_importance().head(12)
        if not feature_df.empty:
            fig = px.bar(
                feature_df.sort_values("importance"),
                x="importance",
                y="feature",
                orientation="h",
                title="Feature Importance",
                color="importance",
                color_continuous_scale=[[0, "#27f5ee"], [1, "#8b5cf6"]],
            )
            fig.update_layout(coloraxis_showscale=False)
            st.plotly_chart(chart_layout(fig, height=420), use_container_width=True)
    render_section_header("Model Snapshot", "Key artifact metadata exposed by the serving layer.")
    st.code(
        f"Model: {info.get('model_name')}\nArtifacts: {info.get('trained_artifact_dir')}\nFeature count: {info.get('feature_count')}\nDecision threshold: {info.get('decision_threshold')}\nHybrid detection: {info.get('hybrid_detection')}",
        language="text",
    )


def render_system_monitoring() -> None:
    render_hero(
        "System Monitoring",
        "Observe API health, resource pressure, and platform events through a clean operations view.",
        badges=[render_badge("Uptime", "good"), render_badge("Observability", "warn")],
        show_metrics=False,
    )
    health = client.health()
    try:
        import psutil

        cpu_percent = psutil.cpu_percent(interval=None)
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage(str(PROJECT_ROOT)).percent
    except Exception:
        cpu_percent = 0.0
        memory_percent = 0.0
        disk_percent = 0.0
    render_kpi_grid(
        [
            {"icon": "🟢", "label": "Service Status", "value": str(health.get("status", "unknown")).title(), "note": "API and model service state", "badge": render_badge("Healthy" if health.get("status") == "healthy" else "Check", "good" if health.get("status") == "healthy" else "warn")},
            {"icon": "🧠", "label": "Model Ready", "value": str(health.get("model_ready", False)), "note": "Artifact loading status", "badge": render_badge("Inference", "good")},
            {"icon": "⚙️", "label": "CPU Utilization", "value": f"{cpu_percent:.1f}%", "note": "Current host pressure", "badge": render_badge("Compute", "warn")},
            {"icon": "💾", "label": "Memory Utilization", "value": f"{memory_percent:.1f}%", "note": "Working set pressure", "badge": render_badge("Memory", "warn")},
        ]
    )
    render_section_header("Resource Pressure", "Quick operator view of machine-level saturation and storage health.")
    resource_fig = go.Figure()
    resource_fig.add_trace(go.Bar(name="CPU", x=["CPU", "Memory", "Disk"], y=[cpu_percent, memory_percent, disk_percent], marker_color=["#27f5ee", "#8b5cf6", "#f59e0b"], text=[f"{cpu_percent:.1f}%", f"{memory_percent:.1f}%", f"{disk_percent:.1f}%"], textposition="auto"))
    resource_fig.update_yaxes(range=[0, 100], title_text="Utilization %")
    st.plotly_chart(chart_layout(resource_fig, height=320, title="Host Utilization"), use_container_width=True)
    render_section_header("Latest API Logs", "Recent runtime events from the local logging surface.")
    log_path = PROJECT_ROOT / "logs" / "api.log"
    if log_path.exists():
        st.code("\n".join(log_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-25:]), language="text")
    else:
        st.markdown('<div class="empty-card">No logs available yet.</div>', unsafe_allow_html=True)


def render_about() -> None:
    render_hero(
        "About Project",
        "Enterprise-grade phishing detection platform built for production deployment and security operations.",
        badges=[render_badge("Production-ready", "good"), render_badge("FastAPI + Streamlit", "warn")],
        show_metrics=False,
    )
    st.markdown(
        """
        <div class="about-stack">
          <div class="surface-card">
            <div class="panel-title">Architecture</div>
            <div class="panel-subtitle">The platform separates training, prediction serving, and the Streamlit command center.</div>
          </div>
          <div class="panel-card">
            <div class="panel-title">Workflow</div>
            <div class="panel-subtitle">1. Raw phishing data is ingested and validated.<br>2. Features are transformed and the best model is trained.<br>3. The API loads the persisted model and serves real-time predictions.<br>4. Streamlit visualizes threat posture, operations, and model intelligence.</div>
          </div>
          <div class="panel-card">
            <div class="panel-title">Tech Stack</div>
            <div class="panel-subtitle">FastAPI, Streamlit, Plotly, scikit-learn, JSONL prediction history, and Docker-based deployment targets.</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


PAGES = {
    "Executive Dashboard": render_executive,
    "Real-Time URL Detection": render_real_time,
    "Threat Analytics": render_threat_analytics,
    "Batch Prediction": render_batch_prediction,
    "Model Intelligence": render_model_intelligence,
    "System Monitoring": render_system_monitoring,
    "About Project": render_about,
}


def main() -> None:
    st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    apply_theme()
    if "active_section" not in st.session_state:
        st.session_state["active_section"] = None
    # If a hero action set `active_section` on the previous run, map it to the
    # sidebar title and set the widget-backed session key *before* we create
    # the radio. Only perform this mapping when the navigation was initiated
    # by a hero button (transient `hero_nav_pending`) so we don't clobber a
    # user's manual radio selection.
    active = st.session_state.get("active_section")
    hero_nav_pending = bool(st.session_state.get("hero_nav_pending"))
    if hero_nav_pending and active in {"scanner", "analytics"}:
        st.session_state["phishguard-nav"] = {"scanner": "Real-Time URL Detection", "analytics": "Threat Analytics"}[active]
    selected = render_sidebar()
    # Resolve hero-driven navigation first. This avoids a race where the
    # sidebar value can still reflect the previous selection during the first
    # rerun, which can make users feel like they need to tap twice.
    active = st.session_state.get("active_section")
    hero_nav_pending = bool(st.session_state.get("hero_nav_pending"))
    if hero_nav_pending and active in {"scanner", "analytics"}:
        st.session_state.pop("hero_nav_pending", None)
        if active == "scanner":
            render_real_time(embedded=False)
            return
        if active == "analytics":
            render_threat_analytics(embedded=False)
            return

    # If the user manually chose a different sidebar item, prefer the sidebar
    # selection and clear stale `active_section` so it won't override clicks.
    if active in {"scanner", "analytics"}:
        mapped = {"scanner": "Real-Time URL Detection", "analytics": "Threat Analytics"}[active]
        if selected != mapped:
            st.session_state["active_section"] = None
            active = None

    # Allow explicit widget-backed navigation to win (this is the normal
    # interactive path). If `active_section` still requests an embedded
    # render, honor it first; otherwise use the radio selection.
    if active == "scanner":
        render_real_time(embedded=False)
        return
    if active == "analytics":
        render_threat_analytics(embedded=False)
        return

    selected = st.session_state.get("phishguard-nav", selected)
    PAGES[selected]()


if __name__ == "__main__":
    main()
