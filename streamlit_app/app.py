"""
PhishGuard AI — Enterprise Cyber SOC & Threat Intelligence Dashboard.

Production-ready Streamlit command center for real-time phishing detection,
threat telemetry, historical analytics, batch prediction, and model intelligence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import io
import os
from pathlib import Path
import re
import sys
import time
import types
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# Setup paths and service resolution
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure streamlit_app folder is in sys.path for local imports
STREAMLIT_DIR = Path(__file__).resolve().parent
if str(STREAMLIT_DIR) not in sys.path:
    sys.path.insert(0, str(STREAMLIT_DIR))

# Import local SOC design system and SVG icon library
try:
    from icons import get_svg_icon, render_icon_box
    from styles import apply_theme, chart_layout, dual_gauge
except ImportError:
    from streamlit_app.icons import get_svg_icon, render_icon_box
    from streamlit_app.styles import apply_theme, chart_layout, dual_gauge


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
        pass


_load_streamlit_secrets_into_environment()

APP_NAME = "PhishGuard AI"
APP_TAGLINE = "Enterprise Phishing Detection & Cyber Threat Intelligence"
LOCAL_TIMEZONE = ZoneInfo(os.getenv("APP_TIMEZONE", "Asia/Kolkata"))
LOCAL_TIMEZONE_LABEL = os.getenv("APP_TIMEZONE_LABEL", "IST")

NAV_ITEMS = [
    {"title": "Executive Dashboard", "icon": "compass", "subtitle": "Operations overview"},
    {"title": "Real-Time URL Detection", "icon": "radar", "subtitle": "Instant analysis"},
    {"title": "Threat Analytics", "icon": "bar-chart", "subtitle": "Trends and risk"},
    {"title": "Batch Prediction", "icon": "layers", "subtitle": "Bulk scanning"},
    {"title": "Model Intelligence", "icon": "cpu", "subtitle": "Metrics and features"},
    {"title": "System Monitoring", "icon": "server", "subtitle": "Health and logs"},
    {"title": "About Project", "icon": "info", "subtitle": "Architecture and stack"},
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


@st.cache_resource(show_spinner="Loading detection model artifacts...")
def _get_model_service():
    module = _load_module_from_path("app.services.model_service", _services_dir / "model_service.py")
    return getattr(module, "model_service")


model_service = _get_model_service()


@st.cache_resource
def _get_prediction_store():
    module = _load_module_from_path("app.services.prediction_store", _services_dir / "prediction_store.py")
    return getattr(module, "prediction_store")


prediction_store = _get_prediction_store()


# ==============================================================================
# Helper Formatting Functions
# ==============================================================================

def format_percentage(value: float) -> str:
    return f"{value * 100:.1f}%"


def to_local_timestamp(value: Any) -> pd.Timestamp:
    timestamp = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(timestamp):
        return pd.NaT
    return timestamp.tz_convert(LOCAL_TIMEZONE)


def format_display_time(value: Any) -> str:
    timestamp = to_local_timestamp(value)
    if pd.isna(timestamp):
        return ""
    return f"{timestamp.strftime('%Y-%m-%d %H:%M')} {LOCAL_TIMEZONE_LABEL}"


def format_date_span(start_date: Any, end_date: Any) -> str:
    if start_date == end_date:
        return str(start_date)
    return f"{start_date}<br><span style='font-size:0.8em;color:#94a3b8;'>to</span><br>{end_date}"


def render_badge(label: str, tone: str = "info", icon: Optional[str] = None, has_dot: bool = True) -> str:
    """Render a standardized enterprise SOC pill badge."""
    dot_html = '<span class="soc-pill-dot"></span>' if has_dot else ""
    icon_html = f"{get_svg_icon(icon, size=14)} " if icon else ""
    return f'<span class="soc-pill {tone}">{dot_html}{icon_html}{label}</span>'


def render_section_header(
    title: str,
    subtitle: str = "",
    icon: Optional[str] = None,
    right_html: str = "",
    anchor_id: Optional[str] = None,
) -> None:
    """Render a clean, prominent section header with optional icon and metadata."""
    anchor_attr = f' id="{anchor_id}"' if anchor_id else ""
    icon_html = f"{get_svg_icon(icon, size=20, color='#00e5ff')} " if icon else ""
    st.markdown(
        f"""
        <div class="soc-section-head"{anchor_attr}>
            <div>
                <div class="soc-section-title">{icon_html}{title}</div>
                {f'<div class="soc-section-subtitle">{subtitle}</div>' if subtitle else ''}
            </div>
            {f'<div>{right_html}</div>' if right_html else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_hero(
    title: str,
    subtitle: str,
    kicker: str = "Enterprise Cyber Threat Intelligence",
    badges: Optional[List[str]] = None,
    actions: Optional[List[Dict[str, str]]] = None,
    show_features: bool = True,
) -> None:
    """Render the standardized enterprise SOC Command Hero header."""
    badges = badges or [render_badge("AI Detection Active", "good", icon="shield-check")]
    badge_markup = "".join(f"<span>{b}</span>" for b in badges)
    
    features_html = ""
    if show_features:
        features_html = f"""
        <div class="soc-feature-grid">
            <div class="soc-feature-card">
                {render_icon_box('radar', tone='cyan', size='md')}
                <div class="soc-feature-content">
                    <div class="soc-feature-kicker">Live Scanning</div>
                    <div class="soc-feature-title">AI URL Analysis</div>
                    <div class="soc-feature-desc">Real-time lexical, structural, and heuristic evaluation of suspicious links.</div>
                </div>
            </div>
            <div class="soc-feature-card">
                {render_icon_box('crosshair', tone='indigo', size='md')}
                <div class="soc-feature-content">
                    <div class="soc-feature-kicker">Risk Scoring</div>
                    <div class="soc-feature-title">Confidence Driven</div>
                    <div class="soc-feature-desc">Calibrated probability distributions paired with rule-engine threat telemetry.</div>
                </div>
            </div>
            <div class="soc-feature-card">
                {render_icon_box('activity', tone='emerald', size='md')}
                <div class="soc-feature-content">
                    <div class="soc-feature-kicker">SOC Observability</div>
                    <div class="soc-feature-title">Security Analytics</div>
                    <div class="soc-feature-desc">Fleet-wide threat patterns, historical forensics, and operational intelligence.</div>
                </div>
            </div>
        </div>
        """

    st.markdown(
        f"""
        <div class="soc-hero-card">
            <div class="soc-hero-top">
                <div class="soc-hero-copy">
                    <div class="soc-eyebrow">
                        {get_svg_icon('shield', size=16, color='#00e5ff')}
                        {kicker}
                    </div>
                    <h1 class="soc-hero-title">{title}</h1>
                    <div class="soc-hero-subtitle">{subtitle}</div>
                </div>
                <div class="soc-hero-badges">{badge_markup}</div>
            </div>
            {features_html}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if actions:
        action_columns = st.columns(len(actions))
        for col, action in zip(action_columns, actions):
            with col:
                btn_icon = action.get("icon", "arrow-right")
                if st.button(f"{action['label']}", use_container_width=True, key=action["key"]):
                    st.session_state["active_section"] = action["target"]
                    st.session_state["hero_nav_pending"] = True
                    st.rerun()


def render_kpi_grid(cards: List[Dict[str, Any]]) -> None:
    """Render standardized, equal-height KPI / Stat Cards with 48px SVG icons."""
    if not cards:
        return
    st.markdown('<div style="margin-top: 0.5rem; margin-bottom: 0.25rem;"></div>', unsafe_allow_html=True)
    columns = st.columns(len(cards))
    for col, card in zip(columns, cards):
        with col:
            value = str(card["value"])
            value_class = card.get("value_class", "")
            if card.get("label") == "Date Span":
                value_class = f"{value_class} compact".strip()
                dates = re.findall(r"\d{4}-\d{2}-\d{2}", value)
                if len(dates) >= 2:
                    value = dates[0] if dates[0] == dates[1] else format_date_span(dates[0], dates[1])
            
            icon_name = card.get("icon", "shield")
            icon_tone = card.get("tone", "cyan")
            icon_box_html = render_icon_box(icon_name, tone=icon_tone, size="md")
            badge_html = card.get("badge", "")

            card_html = f"""
            <div class="soc-kpi-card">
                <div class="soc-kpi-top">
                    {icon_box_html}
                    <div>{badge_html}</div>
                </div>
                <div class="soc-kpi-label">{card["label"]}</div>
                <div class="soc-kpi-value {value_class}">{value}</div>
                <div class="soc-kpi-note">{card.get("note", "")}</div>
            </div>
            """
            st.markdown(card_html, unsafe_allow_html=True)
    st.markdown('<div style="margin-bottom: 0.85rem;"></div>', unsafe_allow_html=True)


def render_empty_state(title: str, subtitle: str = "", icon: str = "search") -> None:
    """Render a polished empty state placeholder."""
    icon_box = render_icon_box(icon, tone="slate", size="lg")
    st.markdown(
        f"""
        <div class="soc-empty-state">
            <div class="soc-empty-icon">{icon_box}</div>
            <div class="soc-empty-title">{title}</div>
            {f'<div class="soc-empty-desc">{subtitle}</div>' if subtitle else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==============================================================================
# API & Data Client Layer
# ==============================================================================

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
        data["history_backend"] = prediction_store.backend_name
        data["history_error"] = prediction_store.mongo_error
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


@st.cache_data(ttl=30, show_spinner=False)
def _cached_history(limit: int = 300) -> List[Dict]:
    return client.recent_history(limit=limit)


@st.cache_data(ttl=30, show_spinner=False)
def _cached_threat_stats() -> Dict:
    return client.threat_stats()


def load_demo_url() -> None:
    demo_url = st.session_state.get("phishguard-demo-url", "")
    if demo_url and demo_url != "Select a sample phishing URL":
        st.session_state["phishguard-scan-url"] = demo_url


# ==============================================================================
# Sidebar Renderer
# ==============================================================================

def render_sidebar() -> str:
    with st.sidebar:
        shield_icon = render_icon_box("shield", tone="cyan", size="md")
        st.markdown(
            f"""
            <div class="soc-sidebar-header">
                <div class="soc-sidebar-brand">
                    {shield_icon}
                    <div class="soc-brand-info">
                        <div class="soc-brand-kicker">PhishGuard AI</div>
                        <div class="soc-brand-title">Threat Console</div>
                    </div>
                </div>
                <div class="soc-brand-subtitle">
                    Next-gen ML phishing detection and SOC cyber threat intelligence.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(render_badge("Active Telemetry Engine", "good", icon="activity"), unsafe_allow_html=True)
        st.markdown('<div class="soc-sidebar-nav-title">SOC Navigation</div>', unsafe_allow_html=True)

        nav_labels = {
            item["title"]: f'{item["title"]}\n{item["subtitle"]}'
            for item in NAV_ITEMS
        }

        selected = st.radio(
            "Navigation",
            [item["title"] for item in NAV_ITEMS],
            format_func=lambda value: nav_labels[value],
            label_visibility="collapsed",
            key="phishguard-nav",
        )

        st.markdown('<div class="soc-divider"></div>', unsafe_allow_html=True)
        if st.button("Refresh Telemetry", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    return selected


# ==============================================================================
# Page 1: Executive Dashboard
# ==============================================================================

def render_executive() -> None:
    stats = _cached_threat_stats()
    info = client.model_info()
    health = client.health()
    active_section = st.session_state.get("active_section")
    history_backend = health.get("history_backend", "file")

    render_hero(
        "PhishGuard AI Command Center",
        "Unified cybersecurity dashboard for real-time URL threat detection, live telemetry, and risk classification.",
        badges=[
            render_badge("Live Telemetry", "good", icon="activity"),
            render_badge("URL Threat Analysis", "warn", icon="radar"),
            render_badge(str(health.get("status", "Healthy")).title(), "good" if health.get("status") == "healthy" else "warn", icon="check-circle"),
            render_badge("MongoDB Clustered" if history_backend == "mongo" else "Local Storage", "good" if history_backend == "mongo" else "neutral", icon="database"),
        ],
        actions=[
            {"label": "Scan Suspicious URL", "target": "scanner", "key": "home-open-scanner", "icon": "radar"},
            {"label": "Open Threat Analytics", "target": "analytics", "key": "home-open-analytics", "icon": "bar-chart"},
        ],
        show_features=True,
    )

    st.markdown('<div style="height: 0.85rem;"></div>', unsafe_allow_html=True)

    render_kpi_grid(
        [
            {
                "icon": "shield",
                "tone": "cyan",
                "label": "Total Scans",
                "value": f"{stats['total_predictions']}",
                "note": "Tracked URL detections",
                "badge": render_badge("Realtime", "good"),
            },
            {
                "icon": "shield-alert",
                "tone": "crimson",
                "label": "Phishing Flags",
                "value": f"{stats['phishing_count']}",
                "note": "Malicious threats quarantined",
                "badge": render_badge("Alerting", "danger"),
            },
            {
                "icon": "shield-check",
                "tone": "emerald",
                "label": "Legitimate URLs",
                "value": f"{stats['legitimate_count']}",
                "note": "Verified safe traffic",
                "badge": render_badge("Trusted", "good"),
            },
            {
                "icon": "crosshair",
                "tone": "indigo",
                "label": "Model F1 Score",
                "value": f"{info.get('metrics', {}).get('f1_score', 0):.3f}",
                "note": "Serving snapshot benchmark",
                "badge": render_badge("Production", "warn"),
            },
        ]
    )

    if history_backend != "mongo":
        st.markdown('<div style="height: 0.6rem;"></div>', unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="soc-panel-card" style="margin-top: 0.5rem; margin-bottom: 1.75rem;">
                <div class="soc-panel-title">
                    {get_svg_icon('database', size=18, color='#f59e0b')}
                    Storage Telemetry Notice
                </div>
                <div class="soc-panel-subtitle">
                    Prediction history is currently persisted in local JSONL storage. To enable durable clustered multi-node history, configure <code>MONGO_DB_URL</code> in your environment variables.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if active_section == "scanner":
        render_real_time(embedded=True)
        return
    if active_section == "analytics":
        render_threat_analytics(embedded=True)
        return

    # Visualizations Grid
    left, right = st.columns([1.05, 0.95], vertical_alignment="top")
    with left:
        render_section_header("Threat Distribution Mix", "Monitored outcome ratios across the recent detection window.", icon="pie-chart")
        threat_levels = stats["by_threat_level"]
        if threat_levels and sum(threat_levels.values()) > 0:
            pie = px.pie(
                values=list(threat_levels.values()),
                names=list(threat_levels.keys()),
                hole=0.60,
                color_discrete_sequence=["#00e5ff", "#6366f1", "#f59e0b", "#ef4444", "#10b981"],
            )
            pie.update_traces(textposition="inside", textinfo="percent+label", marker=dict(line=dict(color="#060b13", width=2)))
            st.plotly_chart(chart_layout(pie, height=360, legend="v"), use_container_width=True)
        else:
            render_empty_state("No Threat Data Collected", "Scan suspicious links or load batch datasets to populate distribution metrics.", icon="pie-chart")

    with right:
        render_section_header("Risk Severity Breakdown", "Classified severity clusters prioritizing immediate triage.", icon="bar-chart")
        risk_levels = stats["by_risk_category"]
        if risk_levels and sum(risk_levels.values()) > 0:
            bar = px.bar(
                x=list(risk_levels.keys()),
                y=list(risk_levels.values()),
                color=list(risk_levels.keys()),
                color_discrete_sequence=["#00e5ff", "#6366f1", "#f59e0b", "#ef4444"],
            )
            bar.update_traces(marker_line_color="#060b13", marker_line_width=1.5)
            st.plotly_chart(chart_layout(bar, height=360), use_container_width=True)
        else:
            render_empty_state("No Severity Data Available", "Risk buckets will appear automatically once URL analysis begins.", icon="bar-chart")

    # Time-series Confidence Trend
    trend = stats.get("trend", [])
    if trend:
        render_section_header("Detection Confidence Timeline", "Time-series telemetry of model confidence across recent requests.", icon="activity")
        trend_fig = go.Figure()
        trend_fig.add_trace(
            go.Scatter(
                x=[item["timestamp"] for item in trend],
                y=[item["confidence_score"] * 100 for item in trend],
                mode="lines+markers",
                line={"color": "#00e5ff", "width": 3},
                marker={"size": 6, "color": "#6366f1", "line": {"color": "#00e5ff", "width": 1.5}},
                name="Confidence %",
            )
        )
        trend_fig.update_xaxes(title_text="Timestamp")
        trend_fig.update_yaxes(title_text="Model Confidence (%)", range=[0, 100])
        st.plotly_chart(chart_layout(trend_fig, height=320), use_container_width=True)


# ==============================================================================
# Page 2: Real-Time URL Detection
# ==============================================================================

def render_real_time(embedded: bool = False) -> None:
    if not embedded:
        render_hero(
            "Real-Time Threat Detection",
            "Perform instant lexical, structural, and heuristic threat inspection on suspicious URLs with deep explainability.",
            badges=[
                render_badge("Sub-15ms Latency", "good", icon="zap"),
                render_badge("Hybrid ML + Rules", "warn", icon="cpu"),
            ],
            show_features=False,
        )
    else:
        render_section_header("Real-Time Threat Detection", "Instant URL security triage workbench.", icon="radar", anchor_id="url-scanner")

    # Input Workbench Row
    left, right = st.columns([1.1, 0.9], vertical_alignment="top")
    with left:
        render_section_header("Analyst Workbench", "Select a preset or input a live target URL.", icon="search")
        st.selectbox(
            "Preset Phishing Samples",
            ["Select a sample phishing URL"] + SAMPLE_PHISHING_URLS,
            key="phishguard-demo-url",
            on_change=load_demo_url,
        )
        st.markdown("<div style='height: 0.3rem;'></div>", unsafe_allow_html=True)
        url = st.text_input(
            "Target URL for Inspection",
            placeholder="https://secure-login.suspicious-domain.com/auth",
            key="phishguard-scan-url",
        )
        st.markdown("<div style='height: 0.4rem;'></div>", unsafe_allow_html=True)
        analyze = st.button("Inspect Target URL", use_container_width=True, key="phishguard-analyze-url")

    with right:
        render_section_header("Inspection Pipeline", "Multi-layered heuristic & ML triage workflow.", icon="layers")
        st.markdown(
            f"""
            <div class="soc-panel-card">
                <div class="soc-panel-title">
                    {get_svg_icon('activity', size=18, color='#00e5ff')}
                    Automated Verification Stages
                </div>
                <div class="soc-panel-subtitle">
                    <strong>1. Structural Lexical Extraction:</strong> Inspects protocol, host, path, Shannon entropy, and suspicious n-grams.<br>
                    <strong>2. Heuristic Indicator Matrix:</strong> Checks credential keywords, IP URLs, port anomalies, and brand spoofing.<br>
                    <strong>3. Model Inference & Explainability:</strong> Scores through trained ensemble and generates feature impact breakdown.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown('<div class="soc-divider"></div>', unsafe_allow_html=True)
    render_section_header("Triage Assessment & Findings", "Structured detection report and risk attribution.", icon="shield")

    if not analyze:
        render_empty_state("Ready for URL Inspection", "Paste a target URL or pick a demo sample above and click 'Inspect Target URL' to run live forensics.", icon="radar")
        return

    if not url.strip():
        render_empty_state("Target URL Required", "Please enter a valid URL in the input field to perform security analysis.", icon="alert-triangle")
        return

    progress = st.progress(0, text="Initializing threat scan...")
    with st.status("Running Deep Threat Analysis", expanded=True) as status:
        status.write("Extracting URL structure, tokens, and domain features...")
        time.sleep(0.12)
        progress.progress(35, text="Evaluating phishing indicators & TF-IDF similarity...")
        status.write("Checking credential harvesting indicators and brand impersonation...")
        time.sleep(0.12)
        progress.progress(70, text="Executing ML model inference...")
        try:
            result = client.predict_url(url.strip())
        except RuntimeError as exc:
            status.update(label="Model Service Unavailable", state="error")
            st.error(str(exc))
            return
        time.sleep(0.10)
        progress.progress(100, text="Analysis complete")
        status.update(label="Security Analysis Completed", state="complete")
    progress.empty()

    # Extract Results
    prediction = result.get("prediction", "").lower()
    is_phishing = prediction != "legitimate"
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

    verdict_tone = "phishing" if is_phishing else "safe"
    verdict_badge_tone = "danger" if is_phishing else "good"
    verdict_tag = "THREAT DETECTED" if is_phishing else "SAFE / LEGITIMATE"
    verdict_heading = "Malicious Phishing Vector" if is_phishing else "Verified Legitimate URL"
    verdict_icon = "shield-alert" if is_phishing else "shield-check"
    ai_verdict = "Likely Phishing Attempt" if is_phishing else "Likely Benign Traffic"

    # 1. Verdict Hero Banner
    banner_icon = render_icon_box(verdict_icon, tone="crimson" if is_phishing else "emerald", size="xl")
    st.markdown(
        f"""
        <div class="soc-verdict-banner {verdict_tone}">
            <div class="soc-verdict-left">
                {banner_icon}
                <div>
                    <div class="soc-verdict-tag">{verdict_tag}</div>
                    <div class="soc-verdict-heading">{verdict_heading}</div>
                    <div class="soc-verdict-url">{url.strip()}</div>
                </div>
            </div>
            <div class="soc-verdict-right">
                <div class="soc-verdict-score-box">
                    <div class="soc-verdict-score-label">Certainty</div>
                    <div class="soc-verdict-score-num">{format_percentage(confidence_value)}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Scoreboard Matrix
    st.markdown(
        f"""
        <div class="soc-scoreboard">
            <div class="soc-score-card">
                <div class="soc-score-label">Threat Verdict</div>
                <div class="soc-score-value">{result.get('prediction', 'Unknown').upper()}</div>
                <div class="soc-score-meta">{render_badge(verdict_tag, verdict_badge_tone)}</div>
            </div>
            <div class="soc-score-card">
                <div class="soc-score-label">Confidence Score</div>
                <div class="soc-score-value">{format_percentage(confidence_value)}</div>
                <div class="soc-score-meta">Model probability</div>
            </div>
            <div class="soc-score-card">
                <div class="soc-score-label">Risk Severity</div>
                <div class="soc-score-value">{risk_level.upper()}</div>
                <div class="soc-score-meta">Policy triage category</div>
            </div>
            <div class="soc-score-card">
                <div class="soc-score-label">AI Conclusion</div>
                <div class="soc-score-value" style="font-size: 1.05rem;">{ai_verdict}</div>
                <div class="soc-score-meta">Automated triage summary</div>
            </div>
            <div class="soc-score-card">
                <div class="soc-score-label">Hybrid Threat Score</div>
                <div class="soc-score-value">{format_percentage(risk_score)}</div>
                <div class="soc-score-meta">Heuristic + ML score</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Dual Gauges
    st.plotly_chart(
        dual_gauge(confidence_value, risk_score),
        use_container_width=True,
        config={"displayModeBar": False, "staticPlot": True},
    )

    # 4. Two-Column Findings & Evidence
    findings_left, findings_right = st.columns(2, vertical_alignment="top")
    with findings_left:
        if triggered_indicators:
            tags_html = " ".join(render_badge(ind, "danger", icon="alert-octagon") for ind in triggered_indicators)
            st.markdown(
                f"""
                <div class="soc-panel-card">
                    <div class="soc-panel-title">
                        {get_svg_icon('alert-triangle', size=18, color='#ef4444')}
                        Triggered Threat Indicators ({len(triggered_indicators)})
                    </div>
                    <div class="soc-panel-subtitle" style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.5rem;">
                        {tags_html}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        if suspicious_keywords:
            keywords_html = " ".join(render_badge(kw, "warn", icon="fingerprint") for kw in suspicious_keywords)
            st.markdown(
                f"""
                <div class="soc-panel-card">
                    <div class="soc-panel-title">
                        {get_svg_icon('search', size=18, color='#f59e0b')}
                        Identified Suspicious Keywords
                    </div>
                    <div class="soc-panel-subtitle" style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.5rem;">
                        {keywords_html}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with findings_right:
        if explanation:
            st.markdown(
                f"""
                <div class="soc-panel-card">
                    <div class="soc-panel-title">
                        {get_svg_icon('file-text', size=18, color='#00e5ff')}
                        AI Forensic Explanation
                    </div>
                    <div class="soc-panel-subtitle">{explanation}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        if text_evidence:
            top_ngrams = ", ".join(text_evidence.get("top_ngrams", [])) or "None identified"
            st.markdown(
                f"""
                <div class="soc-panel-card">
                    <div class="soc-panel-title">
                        {get_svg_icon('fingerprint', size=18, color='#818cf8')}
                        TF-IDF Lexical Similarity Analysis
                    </div>
                    <div class="soc-panel-subtitle">
                        <strong>Malicious Similarity:</strong> {text_evidence.get('malicious_similarity', 0.0):.3f} &nbsp;|&nbsp;
                        <strong>Benign Similarity:</strong> {text_evidence.get('benign_similarity', 0.0):.3f}<br>
                        <strong>Matching N-Grams:</strong> <code>{top_ngrams}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # 5. Charts Breakdown (Full Width / Columns)
    c_left, c_right = st.columns(2, vertical_alignment="top")
    with c_left:
        if risk_breakdown:
            breakdown_df = pd.DataFrame(
                [{"indicator": key, "score": float(val)} for key, val in risk_breakdown.items()]
            ).sort_values(by="score", ascending=False)
            if not breakdown_df.empty:
                fig = px.bar(
                    breakdown_df.head(10),
                    x="score",
                    y="indicator",
                    orientation="h",
                    title="Risk Score Component Breakdown",
                    color="score",
                    color_continuous_scale=[[0, "#00e5ff"], [1, "#6366f1"]],
                )
                fig.update_layout(coloraxis_showscale=False, bargap=0.25)
                fig.update_xaxes(range=[0, float(breakdown_df["score"].max() or 1) * 1.15])
                st.plotly_chart(chart_layout(fig, height=360), use_container_width=True)

    with c_right:
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
                    color_continuous_scale=[[0, "#00e5ff"], [1, "#ef4444"]],
                )
                fig.update_layout(coloraxis_showscale=False, bargap=0.25)
                fig.update_xaxes(range=[0, float(contribution_df["impact"].max() or 1) * 1.15])
                st.plotly_chart(chart_layout(fig, height=360), use_container_width=True)

    if reason_codes:
        reasons_formatted = ", ".join(reason_codes)
        st.markdown(
            f"""
            <div class="soc-panel-card">
                <div class="soc-panel-title">
                    {get_svg_icon('alert-octagon', size=18, color='#ef4444')}
                    Heuristic Rule Flagging Reasons
                </div>
                <div class="soc-panel-subtitle">
                    <strong>Rule Signals:</strong> {reasons_formatted} &nbsp;|&nbsp; <strong>Raw Heuristic Score:</strong> {heuristic_score:.2f}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ==============================================================================
# Page 3: Threat Analytics
# ==============================================================================

def render_threat_analytics(embedded: bool = False) -> None:
    if not embedded:
        render_hero(
            "Threat Analytics & Historical Intelligence",
            "Deep forensic analysis of historical phishing detections, risk distributions, and temporal threat patterns.",
            badges=[
                render_badge("Historical Repository", "good", icon="database"),
                render_badge("Trend Forensics", "warn", icon="bar-chart"),
            ],
            show_features=False,
        )

    history = _cached_history(300)
    if not history:
        render_empty_state("No Historical Telemetry Found", "As URLs are scanned or batch files processed, historical detections will populate here.", icon="database")
        return

    df = pd.DataFrame(history)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True).dt.tz_convert(LOCAL_TIMEZONE)
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        render_empty_state("No Valid Timestamps Found", "History records exist, but valid datetime telemetry was not found.", icon="database")
        return

    # Filter Bar
    render_section_header("Forensic Filter Controls", "Slice dataset by prediction outcome, threat level, and time window.", icon="filter", anchor_id="threat-analytics")
    filters = st.columns(3)
    with filters[0]:
        all_preds = sorted(df["prediction"].dropna().unique().tolist())
        prediction_filter = st.multiselect("Prediction Outcome", all_preds, default=all_preds)
    with filters[1]:
        all_threats = sorted(df["threat_level"].dropna().unique().tolist())
        threat_filter = st.multiselect("Threat Severity Tier", all_threats, default=all_threats)
    with filters[2]:
        date_floor = df["timestamp"].dt.date.min()
        date_ceiling = df["timestamp"].dt.date.max()
        date_range = st.date_input("Date Span Filter", value=(date_floor, date_ceiling), format="YYYY-MM-DD")

    start_date, end_date = (date_range if isinstance(date_range, tuple) and len(date_range) == 2 else (date_floor, date_ceiling))
    filtered = df[
        df["prediction"].isin(prediction_filter)
        & df["threat_level"].isin(threat_filter)
        & (df["timestamp"].dt.date >= start_date)
        & (df["timestamp"].dt.date <= end_date)
    ]

    render_kpi_grid(
        [
            {
                "icon": "layers",
                "tone": "cyan",
                "label": "Visible Events",
                "value": f"{len(filtered)}",
                "note": "Filtered security events",
                "badge": render_badge("Filtered", "good"),
            },
            {
                "icon": "crosshair",
                "tone": "amber",
                "label": "Unique Threat Tiers",
                "value": f"{filtered['threat_level'].nunique()}",
                "note": "Severity levels represented",
                "badge": render_badge("Coverage", "warn"),
            },
            {
                "icon": "clock",
                "tone": "indigo",
                "label": "Date Span",
                "value": f"{start_date} → {end_date}",
                "note": "Forensics observation range",
                "badge": render_badge("Window", "good"),
            },
            {
                "icon": "activity",
                "tone": "emerald",
                "label": "Average Confidence",
                "value": f"{(filtered['confidence_score'].mean() * 100):.1f}%" if not filtered.empty else "0.0%",
                "note": "Mean model certainty",
                "badge": render_badge("Model Metric", "good"),
            },
        ]
    )

    if filtered.empty:
        render_empty_state("No Events Match Filter", "Adjust the multiselect filters or date span above to inspect records.", icon="filter")
        return

    # Visualizations
    col1, col2 = st.columns(2, vertical_alignment="top")
    with col1:
        by_prediction = px.pie(
            filtered,
            names="prediction",
            title="Prediction Classification Split",
            hole=0.55,
            color_discrete_sequence=["#00e5ff", "#6366f1", "#ef4444"],
        )
        by_prediction.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(chart_layout(by_prediction, height=360, legend="v"), use_container_width=True)

    with col2:
        by_threat = px.histogram(
            filtered,
            x="threat_level",
            color="prediction",
            title="Threat Severity Distribution",
            barmode="group",
            color_discrete_sequence=["#00e5ff", "#6366f1"],
        )
        st.plotly_chart(chart_layout(by_threat, height=360), use_container_width=True)

    daily = filtered.assign(date=filtered["timestamp"].dt.date).groupby(["date", "prediction"]).size().reset_index(name="count")
    trend = px.line(
        daily,
        x="date",
        y="count",
        color="prediction",
        markers=True,
        title="Daily Incident Detection Trend",
        color_discrete_sequence=["#00e5ff", "#ef4444"],
    )
    st.plotly_chart(chart_layout(trend, height=340), use_container_width=True)

    # Telemetry Feed Table
    render_section_header("Recent Incident Telemetry Feed", f"Displaying latest 15 records from {len(filtered)} matching events.", icon="file-text")
    display_cols = [col for col in ["timestamp", "prediction", "threat_level", "risk_category", "confidence_score", "url"] if col in filtered.columns]
    recent_display = filtered.sort_values("timestamp", ascending=False).head(15)[display_cols].copy()
    if "timestamp" in recent_display.columns:
        recent_display["timestamp"] = recent_display["timestamp"].apply(format_display_time)
        recent_display = recent_display.rename(columns={"timestamp": "detection_time"})
    if "confidence_score" in recent_display.columns:
        recent_display["confidence_score"] = recent_display["confidence_score"].apply(lambda v: f"{float(v)*100:.1f}%")
    st.dataframe(recent_display, use_container_width=True, hide_index=True)


# ==============================================================================
# Page 4: Batch Prediction
# ==============================================================================

def render_batch_prediction() -> None:
    render_hero(
        "Batch URL Threat Scanning",
        "High-throughput CSV ingestion and bulk inference engine for enterprise threat intelligence feeds.",
        badges=[
            render_badge("Bulk Ingestion", "good", icon="layers"),
            render_badge("Export Formats", "warn", icon="download"),
        ],
        show_features=False,
    )

    uploader_col, notes_col = st.columns([1.1, 0.9], vertical_alignment="top")
    with uploader_col:
        render_section_header("CSV Ingestion Dropzone", "Upload CSV containing candidate URLs.", icon="upload-cloud")
        uploaded = st.file_uploader("Upload CSV", type=["csv"], label_visibility="collapsed")
    with notes_col:
        render_section_header("Schema Requirements", "Expected format and processing guidelines.", icon="info")
        st.markdown(
            f"""
            <div class="soc-panel-card">
                <div class="soc-panel-title">
                    {get_svg_icon('file-text', size=18, color='#00e5ff')}
                    CSV Column Guidelines
                </div>
                <div class="soc-panel-subtitle">
                    Ensure your CSV includes a <code>url</code> column, or the standard URL feature matrix columns. The platform preserves all original columns while appending detection metadata (<code>prediction</code>, <code>confidence_score</code>, <code>threat_level</code>, <code>risk_category</code>).
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if not uploaded:
        render_empty_state("Upload CSV Dataset", "Select or drop a CSV file in the dropzone above to begin batch scoring.", icon="upload-cloud")
        return

    try:
        dataframe = pd.read_csv(uploaded)
    except Exception as exc:
        st.error(f"Failed to parse CSV file: {exc}")
        return

    render_section_header("Dataset Preview", f"Detected {len(dataframe)} rows and {len(dataframe.columns)} columns in uploaded file.", icon="search")
    st.dataframe(dataframe.head(10), use_container_width=True, hide_index=True)

    if st.button("Execute Bulk Threat Scan", use_container_width=True):
        with st.status("Executing Bulk Security Scan", expanded=True) as status:
            status.write("Validating columns and parsing URLs...")
            time.sleep(0.15)
            status.write("Running vectorized inference across model layers...")
            predictions = client.predict_batch(dataframe)
            status.update(label=f"Batch Scan Completed ({len(predictions)} records processed)", state="complete")

        st.success(f"Successfully processed and classified {len(predictions)} security records.")
        st.dataframe(predictions, use_container_width=True, hide_index=True)

        st.download_button(
            "Download Classified Results CSV",
            data=predictions.to_csv(index=False).encode("utf-8"),
            file_name="phishguard_batch_detections.csv",
            mime="text/csv",
            use_container_width=True,
        )


# ==============================================================================
# Page 5: Model Intelligence
# ==============================================================================

def render_model_intelligence() -> None:
    render_hero(
        "Model Intelligence & Explainability",
        "Deep inspection of machine learning performance, evaluation benchmarks, and feature attribution weights.",
        badges=[
            render_badge("Random Forest Ensemble", "good", icon="cpu"),
            render_badge("Calibrated Thresholds", "warn", icon="crosshair"),
        ],
        show_features=False,
    )

    info = client.model_info()
    metrics = info.get("metrics", {})

    render_kpi_grid(
        [
            {
                "icon": "crosshair",
                "tone": "cyan",
                "label": "Model Accuracy",
                "value": f"{metrics.get('accuracy', 0.0):.3f}",
                "note": "Overall classification rate",
                "badge": render_badge("Evaluation", "good"),
            },
            {
                "icon": "shield-check",
                "tone": "indigo",
                "label": "Precision Benchmark",
                "value": f"{metrics.get('precision', 0.0):.3f}",
                "note": "False positive minimization",
                "badge": render_badge("Reliability", "good"),
            },
            {
                "icon": "radar",
                "tone": "emerald",
                "label": "Recall Coverage",
                "value": f"{metrics.get('recall', 0.0):.3f}",
                "note": "Phishing detection sensitivity",
                "badge": render_badge("Threat Capture", "good"),
            },
            {
                "icon": "activity",
                "tone": "amber",
                "label": "Harmonic F1 Score",
                "value": f"{metrics.get('f1_score', 0.0):.3f}",
                "note": "Balanced precision/recall",
                "badge": render_badge("Benchmark", "warn"),
            },
        ]
    )

    top, bottom = st.columns([1, 1], vertical_alignment="top")
    with top:
        render_section_header("Evaluation Confusion Matrix", "True vs. predicted distribution on the test split.", icon="crosshair")
        cm = go.Figure(
            data=go.Heatmap(
                z=[
                    [metrics.get("true_negative", 0), metrics.get("false_positive", 0)],
                    [metrics.get("false_negative", 0), metrics.get("true_positive", 0)],
                ],
                x=["Predicted Safe", "Predicted Phishing"],
                y=["Actual Safe", "Actual Phishing"],
                colorscale=[[0, "#060b13"], [0.35, "#00e5ff"], [1, "#6366f1"]],
                hovertemplate="Count: %{z}<extra></extra>",
            )
        )
        cm.update_coloraxes(colorbar_thickness=12)
        st.plotly_chart(chart_layout(cm, height=360), use_container_width=True)

    with bottom:
        render_section_header("Feature Importance Weights", "Top predictive feature signals driving classification.", icon="bar-chart")
        feature_df = client.feature_importance().head(12)
        if not feature_df.empty:
            fig = px.bar(
                feature_df.sort_values("importance"),
                x="importance",
                y="feature",
                orientation="h",
                color="importance",
                color_continuous_scale=[[0, "#00e5ff"], [1, "#6366f1"]],
            )
            fig.update_layout(coloraxis_showscale=False, bargap=0.25)
            st.plotly_chart(chart_layout(fig, height=360), use_container_width=True)

    render_section_header("Serving Artifact Snapshot", "Runtime configuration and serialization metadata.", icon="terminal")
    st.code(
        f"Active Model: {info.get('model_name')}\n"
        f"Artifact Location: {info.get('trained_artifact_dir')}\n"
        f"Feature Vector Count: {info.get('feature_count')}\n"
        f"Decision Threshold: {info.get('decision_threshold')}\n"
        f"Hybrid Detection Engine: {info.get('hybrid_detection')}",
        language="text",
    )


# ==============================================================================
# Page 6: System Monitoring
# ==============================================================================

def render_system_monitoring() -> None:
    render_hero(
        "System Observability & Monitoring",
        "Monitor host resource pressure, inference engine health, and runtime security logging streams.",
        badges=[
            render_badge("SOC Node Health", "good", icon="server"),
            render_badge("Telemetry Live", "warn", icon="activity"),
        ],
        show_features=False,
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
            {
                "icon": "server",
                "tone": "emerald" if health.get("status") == "healthy" else "amber",
                "label": "Engine Service Status",
                "value": str(health.get("status", "Unknown")).title(),
                "note": "API & inference service health",
                "badge": render_badge("Online" if health.get("status") == "healthy" else "Check", "good" if health.get("status") == "healthy" else "warn"),
            },
            {
                "icon": "cpu",
                "tone": "cyan",
                "label": "Model Artifact Ready",
                "value": "Active" if health.get("model_ready", False) else "Loading",
                "note": "Serialized model availability",
                "badge": render_badge("Inference Engine", "good"),
            },
            {
                "icon": "activity",
                "tone": "indigo",
                "label": "CPU Utilization",
                "value": f"{cpu_percent:.1f}%",
                "note": "Host processor capacity",
                "badge": render_badge("Compute", "warn" if cpu_percent > 75 else "good"),
            },
            {
                "icon": "hard-drive",
                "tone": "amber",
                "label": "Memory Saturation",
                "value": f"{memory_percent:.1f}%",
                "note": "Resident memory working set",
                "badge": render_badge("Memory", "warn" if memory_percent > 80 else "good"),
            },
        ]
    )

    render_section_header("Host Resource Utilization", "Infrastructure telemetry for host memory, CPU, and disk storage.", icon="bar-chart")
    resource_fig = go.Figure()
    resource_fig.add_trace(
        go.Bar(
            name="Utilization",
            x=["CPU Core Load", "RAM Working Set", "Storage Disk"],
            y=[cpu_percent, memory_percent, disk_percent],
            marker_color=["#00e5ff", "#6366f1", "#f59e0b"],
            text=[f"{cpu_percent:.1f}%", f"{memory_percent:.1f}%", f"{disk_percent:.1f}%"],
            textposition="auto",
        )
    )
    resource_fig.update_yaxes(range=[0, 100], title_text="Utilization (%)")
    st.plotly_chart(chart_layout(resource_fig, height=300), use_container_width=True)

    render_section_header("Runtime Engine Logs", "Real-time log telemetry captured from the API and inference workers.", icon="terminal")
    log_path = PROJECT_ROOT / "logs" / "api.log"
    if log_path.exists():
        log_lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-30:]
        log_content = "\n".join(log_lines)
    else:
        log_content = "[SYSTEM] No local file logs present. Logging active on stdout/stderr."

    st.markdown(
        f"""
        <div class="soc-terminal-box">
            <div class="soc-terminal-header">
                <div class="soc-terminal-dots">
                    <span class="soc-terminal-dot" style="background: #ef4444;"></span>
                    <span class="soc-terminal-dot" style="background: #f59e0b;"></span>
                    <span class="soc-terminal-dot" style="background: #10b981;"></span>
                </div>
                <div style="font-family: monospace; font-size: 0.75rem; color: #64748b;">api.log - Real-time stream</div>
            </div>
            <div class="soc-terminal-body">{log_content}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==============================================================================
# Page 7: About Project
# ==============================================================================

def render_about() -> None:
    render_hero(
        "About PhishGuard AI",
        "Enterprise-grade phishing detection and cyber threat intelligence platform engineered for SOC teams.",
        badges=[
            render_badge("Production Ready", "good", icon="shield-check"),
            render_badge("FastAPI + Streamlit", "warn", icon="layers"),
        ],
        show_features=False,
    )

    st.markdown(
        f"""
        <div class="soc-feature-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 1.25rem;">
            <div class="soc-feature-card">
                {render_icon_box('layers', tone='cyan', size='md')}
                <div class="soc-feature-content">
                    <div class="soc-feature-kicker">Core System</div>
                    <div class="soc-feature-title">Modular Architecture</div>
                    <div class="soc-feature-desc">Clean decoupling between ML training pipelines, high-performance FastAPI prediction endpoints, and the Streamlit SOC dashboard.</div>
                </div>
            </div>
            <div class="soc-feature-card">
                {render_icon_box('activity', tone='indigo', size='md')}
                <div class="soc-feature-content">
                    <div class="soc-feature-kicker">Pipeline</div>
                    <div class="soc-feature-title">End-to-End Ingestion</div>
                    <div class="soc-feature-desc">Automatic validation, schema transformation, multi-model evaluation, and persistent model serialization in production artifacts.</div>
                </div>
            </div>
            <div class="soc-feature-card">
                {render_icon_box('cpu', tone='emerald', size='md')}
                <div class="soc-feature-content">
                    <div class="soc-feature-kicker">Technology</div>
                    <div class="soc-feature-title">Enterprise Tech Stack</div>
                    <div class="soc-feature-desc">Python 3.11, scikit-learn, FastAPI, Streamlit, Plotly, Docker, MongoDB, and MLflow experiment tracking.</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="soc-panel-card">
            <div class="soc-panel-title">
                {get_svg_icon('shield', size=18, color='#00e5ff')}
                Threat Detection Workflow
            </div>
            <div class="soc-panel-subtitle">
                <strong>1. Ingestion & Preprocessing:</strong> Raw phishing datasets and live URLs are parsed into structural lexical tokens and domain indicators.<br>
                <strong>2. Feature Transformation:</strong> 30+ engineered signals (Shannon entropy, host length, credential tokens, TF-IDF lexical matches) are normalized.<br>
                <strong>3. Real-Time Inference:</strong> The ensemble model scores probability distributions in sub-15ms latency.<br>
                <strong>4. Explainable Security Telemetry:</strong> Confidence percentages, triggered risk indicators, and feature contributions are delivered immediately to SOC analysts.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==============================================================================
# Main Router
# ==============================================================================

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
    st.set_page_config(
        page_title="PhishGuard AI — Threat Intelligence Console",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    apply_theme()

    if "active_section" not in st.session_state:
        st.session_state["active_section"] = None

    active = st.session_state.get("active_section")
    hero_nav_pending = bool(st.session_state.get("hero_nav_pending"))
    if hero_nav_pending and active in {"scanner", "analytics"}:
        st.session_state["phishguard-nav"] = {
            "scanner": "Real-Time URL Detection",
            "analytics": "Threat Analytics",
        }[active]

    selected = render_sidebar()

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

    if active in {"scanner", "analytics"}:
        mapped = {"scanner": "Real-Time URL Detection", "analytics": "Threat Analytics"}[active]
        if selected != mapped:
            st.session_state["active_section"] = None
            active = None

    if active == "scanner":
        render_real_time(embedded=False)
        return
    if active == "analytics":
        render_threat_analytics(embedded=False)
        return

    selected = st.session_state.get("phishguard-nav", selected)
    try:
        PAGES[selected]()
    except Exception as exc:
        st.error("The selected SOC dashboard view could not be rendered.")
        st.exception(exc)


if __name__ == "__main__":
    main()
