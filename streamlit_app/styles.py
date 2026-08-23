"""Enterprise Cyber SOC Design System CSS and Theme Utilities for PhishGuard AI."""

from __future__ import annotations
import plotly.graph_objects as go


SOC_CSS = """
<style>
/* ==========================================================================
   PhishGuard AI — Enterprise SOC Theme & Design Tokens
   ========================================================================== */

:root {
    /* Color Palette */
    --bg-base: #060b13;
    --bg-surface: #0a1322;
    --bg-card: rgba(13, 23, 40, 0.94);
    --bg-card-hover: rgba(17, 30, 53, 0.98);
    --bg-elevated: rgba(19, 34, 60, 0.95);
    
    /* Precision Borders */
    --border-subtle: rgba(56, 189, 248, 0.14);
    --border-accent: rgba(56, 189, 248, 0.32);
    --border-highlight: rgba(99, 102, 241, 0.35);
    --border-card: rgba(56, 189, 248, 0.12);
    
    /* Accents */
    --accent-cyan: #00e5ff;
    --accent-cyan-dim: rgba(0, 229, 255, 0.12);
    --accent-blue: #3b82f6;
    --accent-indigo: #6366f1;
    
    /* Semantic Threat Tiers */
    --color-safe: #10b981;
    --color-safe-bg: rgba(16, 185, 129, 0.14);
    --color-safe-border: rgba(16, 185, 129, 0.32);
    
    --color-warn: #f59e0b;
    --color-warn-bg: rgba(245, 158, 11, 0.14);
    --color-warn-border: rgba(245, 158, 11, 0.32);
    
    --color-danger: #ef4444;
    --color-danger-bg: rgba(239, 68, 68, 0.15);
    --color-danger-border: rgba(239, 68, 68, 0.35);
    
    --color-info: #38bdf8;
    --color-info-bg: rgba(56, 189, 248, 0.12);
    
    /* Typography Colors */
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --text-code: #38bdf8;
    
    /* Shadows & Elevation */
    --shadow-card: 0 8px 30px rgba(0, 0, 0, 0.42);
    --shadow-hover: 0 12px 38px rgba(0, 0, 0, 0.52), 0 0 24px rgba(0, 229, 255, 0.10);
    --shadow-glow-cyan: 0 0 20px rgba(0, 229, 255, 0.15);
    
    /* Radii */
    --r-sm: 8px;
    --r-md: 12px;
    --r-lg: 16px;
    --r-xl: 20px;
    --r-full: 9999px;
    
    /* Layout Spacing */
    --space-card: 1.35rem;
    --space-grid: 1.15rem;
}

/* ==========================================================================
   Global Base & Typography
   ========================================================================== */

html, body, [class*="css"] {
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
}

html, body {
    background: var(--bg-base) !important;
    overflow-x: hidden;
}

.stApp {
    background:
        radial-gradient(ellipse 90% 50% at 10% -10%, rgba(0, 229, 255, 0.08), transparent 50%),
        radial-gradient(ellipse 80% 50% at 90% 10%, rgba(99, 102, 241, 0.09), transparent 50%),
        linear-gradient(180deg, #070d18 0%, #050912 60%, #03060c 100%) !important;
    color: var(--text-primary);
}

[data-testid="stAppViewContainer"] {
    display: flex !important;
    flex: 1 1 auto !important;
    min-width: 0 !important;
    width: 100% !important;
    transition: all 280ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

[data-testid="stMain"], [data-testid="stAppViewContainer"] > .main {
    display: block !important;
    flex: 1 1 auto !important;
    min-width: 0 !important;
    width: 100% !important;
    padding-left: 0 !important;
    padding-right: 0 !important;
    transition: all 280ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

.block-container {
    padding-top: 1.25rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 100% !important;
    width: 100% !important;
    margin: 0 auto !important;
    padding-left: clamp(1.2rem, 2.8vw, 3.2rem) !important;
    padding-right: clamp(1.2rem, 2.8vw, 3.2rem) !important;
    transition: padding 280ms ease, max-width 280ms ease, width 280ms ease !important;
}

/* Hide Default Streamlit Clutter */
#MainMenu,
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
[data-testid="stDeployButton"] {
    display: none !important;
    visibility: hidden !important;
}

[data-testid="stHeader"] {
    background: transparent !important;
}

/* Collapsed Sidebar Control Button */
[data-testid="collapsedControl"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    z-index: 1002 !important;
    top: 0.9rem !important;
    left: 0.9rem !important;
    transition: all 200ms ease !important;
}

[data-testid="collapsedControl"] button {
    background: rgba(14, 26, 46, 0.95) !important;
    border: 1px solid var(--border-card) !important;
    border-radius: var(--r-md) !important;
    color: var(--accent-cyan) !important;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4) !important;
    min-height: 38px !important;
    width: 38px !important;
    padding: 0 !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    transition: all 160ms ease !important;
}

[data-testid="collapsedControl"] button:hover {
    border-color: var(--accent-cyan) !important;
    background: rgba(20, 38, 68, 0.98) !important;
    transform: scale(1.05) !important;
    box-shadow: 0 0 16px rgba(0, 229, 255, 0.25) !important;
}

/* Equal-Height Column Alignment & Flex Grids */
div[data-testid="stHorizontalBlock"] {
    gap: var(--space-grid) !important;
    align-items: stretch !important;
    transition: all 280ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

div[data-testid="column"], div[data-testid="stColumn"] {
    display: flex !important;
    flex-direction: column !important;
    min-width: 0 !important;
    transition: all 280ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

div[data-testid="column"] > div, div[data-testid="stColumn"] > div {
    width: 100% !important;
    display: flex !important;
    flex-direction: column !important;
    flex: 1 1 auto !important;
}

/* ==========================================================================
   Sidebar Navigation System
   ========================================================================== */

[data-testid="stSidebar"] {
    flex: 0 0 310px !important;
    width: 310px !important;
    min-width: 310px !important;
    max-width: 310px !important;
    background: linear-gradient(180deg, #091220 0%, #060c16 100%) !important;
    border-right: 1px solid var(--border-card) !important;
    box-shadow: 4px 0 24px rgba(0, 0, 0, 0.45) !important;
    transition: width 280ms cubic-bezier(0.4, 0, 0.2, 1), min-width 280ms cubic-bezier(0.4, 0, 0.2, 1), max-width 280ms cubic-bezier(0.4, 0, 0.2, 1), transform 280ms cubic-bezier(0.4, 0, 0.2, 1), opacity 280ms ease !important;
    overflow: hidden !important;
}

[data-testid="stSidebar"][aria-expanded="false"] {
    flex: 0 0 0 !important;
    width: 0 !important;
    min-width: 0 !important;
    max-width: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
    border-right: 0 !important;
    opacity: 0 !important;
    transform: translateX(-100%) !important;
    pointer-events: none !important;
}

[data-testid="stSidebar"][aria-expanded="false"] > div {
    display: none !important;
}

[data-testid="stSidebarContent"] {
    padding: 1.2rem 1.1rem !important;
}

.soc-sidebar-header {
    background: linear-gradient(180deg, rgba(14, 26, 46, 0.95), rgba(9, 17, 31, 0.95));
    border: 1px solid var(--border-card);
    border-radius: var(--r-lg);
    padding: 1.1rem;
    box-shadow: var(--shadow-card);
    margin-bottom: 1.1rem;
}

.soc-sidebar-brand {
    display: flex;
    align-items: center;
    gap: 0.85rem;
}

.soc-brand-info {
    flex: 1;
    min-width: 0;
}

.soc-brand-kicker {
    color: var(--accent-cyan);
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    line-height: 1;
}

.soc-brand-title {
    color: var(--text-primary);
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    margin-top: 0.25rem;
    line-height: 1.2;
}

.soc-brand-subtitle {
    color: var(--text-secondary);
    font-size: 0.82rem;
    margin-top: 0.5rem;
    line-height: 1.45;
}

.soc-sidebar-nav-title {
    color: var(--text-muted);
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    margin: 1.1rem 0 0.6rem 0.2rem;
}

/* Radio Navigation Styling */
.stRadio [role="radiogroup"] {
    display: flex !important;
    flex-direction: column !important;
    gap: 0.45rem !important;
}

.stRadio [role="radiogroup"] > label {
    background: rgba(13, 23, 40, 0.75) !important;
    border: 1px solid rgba(56, 189, 248, 0.08) !important;
    border-radius: var(--r-md) !important;
    padding: 0.65rem 0.85rem !important;
    margin: 0 !important;
    display: flex !important;
    align-items: center !important;
    gap: 0.75rem !important;
    cursor: pointer !important;
    transition: all 160ms cubic-bezier(0.4, 0, 0.2, 1) !important;
    min-height: 48px !important;
    position: relative !important;
    overflow: hidden !important;
}

.stRadio [role="radiogroup"] > label:hover {
    background: rgba(20, 36, 62, 0.9) !important;
    border-color: rgba(56, 189, 248, 0.25) !important;
    transform: translateX(2px) !important;
}

.stRadio [role="radiogroup"] > label[data-checked="true"] {
    background: linear-gradient(90deg, rgba(0, 229, 255, 0.14) 0%, rgba(99, 102, 241, 0.12) 100%) !important;
    border-color: rgba(0, 229, 255, 0.45) !important;
    box-shadow: 0 4px 18px rgba(0, 229, 255, 0.08), inset 3px 0 0 0 var(--accent-cyan) !important;
}

.stRadio [data-baseweb="radio"] {
    display: none !important;
}

.soc-nav-item-content {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
}

.soc-nav-item-icon {
    width: 22px;
    height: 22px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent-cyan);
    flex-shrink: 0;
}

.soc-nav-item-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
}

.soc-nav-item-title {
    color: var(--text-primary);
    font-size: 0.88rem;
    font-weight: 650;
    line-height: 1.2;
}

.soc-nav-item-subtitle {
    color: var(--text-muted);
    font-size: 0.74rem;
    line-height: 1.2;
    margin-top: 0.15rem;
}

/* ==========================================================================
   Icon Box & Container System (Very Important)
   ========================================================================== */

.soc-icon-box {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: transform 180ms ease, box-shadow 180ms ease;
}

.soc-icon-box.tone-cyan {
    background: rgba(0, 229, 255, 0.12);
    border: 1px solid rgba(0, 229, 255, 0.28);
    color: var(--accent-cyan);
    box-shadow: 0 4px 16px rgba(0, 229, 255, 0.10);
}

.soc-icon-box.tone-blue {
    background: rgba(59, 130, 246, 0.14);
    border: 1px solid rgba(59, 130, 246, 0.32);
    color: #60a5fa;
    box-shadow: 0 4px 16px rgba(59, 130, 246, 0.12);
}

.soc-icon-box.tone-indigo {
    background: rgba(99, 102, 241, 0.15);
    border: 1px solid rgba(99, 102, 241, 0.32);
    color: #818cf8;
    box-shadow: 0 4px 16px rgba(99, 102, 241, 0.12);
}

.soc-icon-box.tone-emerald {
    background: var(--color-safe-bg);
    border: 1px solid var(--color-safe-border);
    color: var(--color-safe);
    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.12);
}

.soc-icon-box.tone-amber {
    background: var(--color-warn-bg);
    border: 1px solid var(--color-warn-border);
    color: var(--color-warn);
    box-shadow: 0 4px 16px rgba(245, 158, 11, 0.12);
}

.soc-icon-box.tone-crimson {
    background: var(--color-danger-bg);
    border: 1px solid var(--color-danger-border);
    color: var(--color-danger);
    box-shadow: 0 4px 16px rgba(239, 68, 68, 0.15);
}

.soc-icon-box.tone-slate {
    background: rgba(148, 163, 184, 0.10);
    border: 1px solid rgba(148, 163, 184, 0.20);
    color: var(--text-secondary);
}

/* ==========================================================================
   Badges & Pills Component System
   ========================================================================== */

.soc-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    border-radius: var(--r-full);
    padding: 0.32rem 0.75rem;
    font-size: 0.78rem;
    font-weight: 650;
    line-height: 1;
    white-space: nowrap;
    border: 1px solid transparent;
}

.soc-pill-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}

.soc-pill.good, .soc-pill.safe, .soc-pill.tone-emerald {
    background: var(--color-safe-bg);
    color: #6ee7b7;
    border-color: var(--color-safe-border);
}
.soc-pill.good .soc-pill-dot, .soc-pill.safe .soc-pill-dot { background: #10b981; box-shadow: 0 0 8px #10b981; }

.soc-pill.warn, .soc-pill.suspicious, .soc-pill.tone-amber {
    background: var(--color-warn-bg);
    color: #fcd34d;
    border-color: var(--color-warn-border);
}
.soc-pill.warn .soc-pill-dot, .soc-pill.suspicious .soc-pill-dot { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }

.soc-pill.danger, .soc-pill.phishing, .soc-pill.tone-crimson {
    background: var(--color-danger-bg);
    color: #fca5a5;
    border-color: var(--color-danger-border);
}
.soc-pill.danger .soc-pill-dot, .soc-pill.phishing .soc-pill-dot { background: #ef4444; box-shadow: 0 0 8px #ef4444; }

.soc-pill.info, .soc-pill.tone-cyan {
    background: rgba(0, 229, 255, 0.10);
    color: #a5f3fc;
    border-color: rgba(0, 229, 255, 0.25);
}
.soc-pill.info .soc-pill-dot { background: var(--accent-cyan); box-shadow: 0 0 8px var(--accent-cyan); }

.soc-pill.neutral, .soc-pill.tone-slate {
    background: rgba(148, 163, 184, 0.10);
    color: #cbd5e1;
    border-color: rgba(148, 163, 184, 0.20);
}
.soc-pill.neutral .soc-pill-dot { background: #94a3b8; }

/* ==========================================================================
   Hero & Header System
   ========================================================================== */

.soc-hero-card {
    background: linear-gradient(135deg, rgba(14, 25, 45, 0.96) 0%, rgba(8, 16, 30, 0.96) 100%);
    border: 1px solid var(--border-card);
    border-radius: var(--r-xl);
    padding: 1.6rem 1.8rem;
    box-shadow: var(--shadow-card);
    position: relative;
    overflow: hidden;
    margin-bottom: 1.25rem;
}

.soc-hero-card::before {
    content: "";
    position: absolute;
    top: -40px;
    right: -40px;
    width: 280px;
    height: 280px;
    background: radial-gradient(circle, rgba(0, 229, 255, 0.12) 0%, transparent 70%);
    pointer-events: none;
}

.soc-hero-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1.25rem;
    flex-wrap: wrap;
    position: relative;
    z-index: 1;
}

.soc-hero-copy {
    max-width: clamp(760px, 75vw, 1200px);
    flex: 1 1 auto;
    transition: max-width 280ms ease;
}

.soc-eyebrow {
    color: var(--accent-cyan);
    font-size: 0.74rem;
    font-weight: 800;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
}

.soc-hero-title {
    font-size: clamp(1.8rem, 2.6vw, 2.5rem);
    font-weight: 800;
    color: var(--text-primary);
    line-height: 1.15;
    letter-spacing: -0.02em;
    margin: 0.2rem 0 0.5rem 0;
}

.soc-hero-subtitle {
    color: var(--text-secondary);
    font-size: 1.02rem;
    line-height: 1.55;
    max-width: clamp(680px, 70vw, 1100px);
    transition: max-width 280ms ease;
}

.soc-hero-badges {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
}

/* Feature Cards Grid (3 Equal Columns) */
.soc-feature-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-grid);
    margin-top: 1.25rem;
    position: relative;
    z-index: 1;
}

.soc-feature-card {
    background: rgba(10, 20, 36, 0.75);
    border: 1px solid var(--border-card);
    border-radius: var(--r-md);
    padding: 1.1rem 1.2rem;
    display: flex;
    align-items: flex-start;
    gap: 0.95rem;
    transition: all 160ms ease;
    height: 100%;
}

.soc-feature-card:hover {
    background: rgba(14, 27, 48, 0.90);
    border-color: var(--border-accent);
    transform: translateY(-2px);
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.3);
}

.soc-feature-content {
    flex: 1;
    min-width: 0;
}

.soc-feature-kicker {
    color: var(--text-muted);
    font-size: 0.70rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.12em;
}

.soc-feature-title {
    color: var(--text-primary);
    font-size: 1.05rem;
    font-weight: 750;
    margin: 0.2rem 0 0.3rem 0;
    line-height: 1.25;
}

.soc-feature-desc {
    color: var(--text-secondary);
    font-size: 0.84rem;
    line-height: 1.45;
}

/* ==========================================================================
   Stat / KPI Cards System (Consistent Hierarchy)
   ========================================================================== */

.soc-kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: var(--space-grid);
    align-items: stretch;
    margin-bottom: 1.25rem;
}

.soc-kpi-card {
    background: linear-gradient(180deg, rgba(14, 25, 45, 0.95) 0%, rgba(9, 17, 32, 0.95) 100%);
    border: 1px solid var(--border-card);
    border-radius: var(--r-lg);
    padding: 1.25rem;
    box-shadow: var(--shadow-card);
    display: flex;
    flex-direction: column;
    min-height: 154px;
    height: 100%;
    transition: all 180ms cubic-bezier(0.4, 0, 0.2, 1);
}

.soc-kpi-card:hover {
    border-color: var(--border-accent);
    transform: translateY(-2px);
    box-shadow: var(--shadow-hover);
}

.soc-kpi-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.85rem;
}

.soc-kpi-label {
    color: var(--text-muted);
    font-size: 0.72rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    line-height: 1.2;
}

.soc-kpi-value {
    color: var(--text-primary);
    font-size: clamp(1.8rem, 2.2vw, 2.3rem);
    font-weight: 800;
    line-height: 1.05;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    margin: 0.3rem 0;
}

.soc-kpi-value.compact {
    font-size: clamp(1.35rem, 1.6vw, 1.65rem);
    line-height: 1.2;
}

.soc-kpi-note {
    color: var(--text-secondary);
    font-size: 0.82rem;
    line-height: 1.4;
    margin-top: auto;
    padding-top: 0.4rem;
}

/* ==========================================================================
   Section Headers & Modular Cards
   ========================================================================== */

.soc-section-head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 1rem;
    margin: 1.5rem 0 0.9rem 0;
    flex-wrap: wrap;
}

.soc-section-title {
    font-size: 1.22rem;
    font-weight: 750;
    color: var(--text-primary);
    line-height: 1.2;
    letter-spacing: -0.01em;
    display: flex;
    align-items: center;
    gap: 0.55rem;
}

.soc-section-subtitle {
    color: var(--text-secondary);
    font-size: 0.88rem;
    margin-top: 0.25rem;
    line-height: 1.45;
}

.soc-panel-card {
    background: linear-gradient(180deg, rgba(13, 23, 40, 0.95) 0%, rgba(8, 15, 28, 0.95) 100%);
    border: 1px solid var(--border-card);
    border-radius: var(--r-lg);
    padding: var(--space-card);
    box-shadow: var(--shadow-card);
    display: flex;
    flex-direction: column;
    height: 100%;
    margin-bottom: var(--space-grid);
    transition: border-color 160ms ease, box-shadow 160ms ease;
}

.soc-panel-card:hover {
    border-color: rgba(56, 189, 248, 0.22);
}

.soc-panel-title {
    color: var(--text-primary);
    font-size: 1.05rem;
    font-weight: 750;
    line-height: 1.25;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.3rem;
}

.soc-panel-subtitle {
    color: var(--text-secondary);
    font-size: 0.86rem;
    line-height: 1.5;
    margin-bottom: 0.85rem;
}

.soc-panel-subtitle:last-child {
    margin-bottom: 0;
}

/* ==========================================================================
   Verdict Hero Banner & Scanner Results
   ========================================================================== */

.soc-verdict-banner {
    border-radius: var(--r-lg);
    padding: 1.35rem 1.6rem;
    margin: 1rem 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.2rem;
    flex-wrap: wrap;
    box-shadow: var(--shadow-card);
    border: 1px solid transparent;
}

.soc-verdict-banner.safe {
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.16) 0%, rgba(6, 40, 28, 0.92) 100%);
    border-color: var(--color-safe-border);
}

.soc-verdict-banner.warn {
    background: linear-gradient(135deg, rgba(245, 158, 11, 0.16) 0%, rgba(45, 28, 6, 0.92) 100%);
    border-color: var(--color-warn-border);
}

.soc-verdict-banner.phishing {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(48, 10, 16, 0.92) 100%);
    border-color: var(--color-danger-border);
}

.soc-verdict-left {
    display: flex;
    align-items: center;
    gap: 1.1rem;
}

.soc-verdict-tag {
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.16em;
    text-transform: uppercase;
}

.soc-verdict-banner.safe .soc-verdict-tag { color: var(--color-safe); }
.soc-verdict-banner.warn .soc-verdict-tag { color: var(--color-warn); }
.soc-verdict-banner.phishing .soc-verdict-tag { color: var(--color-danger); }

.soc-verdict-heading {
    font-size: 1.45rem;
    font-weight: 800;
    color: var(--text-primary);
    line-height: 1.2;
    margin-top: 0.15rem;
}

.soc-verdict-url {
    font-family: "JetBrains Mono", Consolas, Menlo, monospace;
    font-size: 0.86rem;
    color: var(--text-code);
    background: rgba(0, 0, 0, 0.35);
    padding: 0.25rem 0.6rem;
    border-radius: var(--r-sm);
    margin-top: 0.45rem;
    display: inline-block;
    word-break: break-all;
}

.soc-verdict-right {
    display: flex;
    align-items: center;
    gap: 1.2rem;
}

.soc-verdict-score-box {
    text-align: right;
}

.soc-verdict-score-label {
    font-size: 0.72rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-muted);
}

.soc-verdict-score-num {
    font-size: 2rem;
    font-weight: 850;
    color: var(--text-primary);
    line-height: 1.1;
}

/* Scoreboard Matrix */
.soc-scoreboard {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: var(--space-grid);
    align-items: stretch;
    margin: 1rem 0;
}

.soc-score-card {
    background: rgba(11, 21, 38, 0.85);
    border: 1px solid var(--border-card);
    border-radius: var(--r-md);
    padding: 1rem;
    display: flex;
    flex-direction: column;
    transition: all 160ms ease;
    height: 100%;
}

.soc-score-card:hover {
    border-color: var(--border-accent);
    transform: translateY(-1px);
}

.soc-score-label {
    color: var(--text-muted);
    font-size: 0.70rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.12em;
}

.soc-score-value {
    color: var(--text-primary);
    font-size: 1.22rem;
    font-weight: 800;
    margin: 0.35rem 0;
    line-height: 1.2;
}

.soc-score-meta {
    color: var(--text-secondary);
    font-size: 0.78rem;
    margin-top: auto;
}

/* ==========================================================================
   Terminal / Monospace Log Container
   ========================================================================== */

.soc-terminal-box {
    background: #040810;
    border: 1px solid var(--border-card);
    border-radius: var(--r-md);
    overflow: hidden;
    box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.6);
}

.soc-terminal-header {
    background: #091220;
    border-bottom: 1px solid var(--border-card);
    padding: 0.55rem 0.95rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.soc-terminal-dots {
    display: flex;
    gap: 6px;
}

.soc-terminal-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
}

.soc-terminal-body {
    padding: 1rem;
    font-family: "JetBrains Mono", Consolas, Menlo, monospace;
    font-size: 0.84rem;
    color: #a5f3fc;
    line-height: 1.6;
    max-height: 380px;
    overflow-y: auto;
    white-space: pre-wrap;
}

/* ==========================================================================
   Empty States & Alert Panels
   ========================================================================== */

.soc-empty-state {
    background: rgba(11, 21, 38, 0.7);
    border: 1px dashed var(--border-card);
    border-radius: var(--r-lg);
    padding: 2.5rem 1.8rem;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    margin: 0.8rem 0;
}

.soc-empty-icon {
    margin-bottom: 0.9rem;
}

.soc-empty-title {
    color: var(--text-primary);
    font-size: 1.1rem;
    font-weight: 700;
    margin-bottom: 0.35rem;
}

.soc-empty-desc {
    color: var(--text-secondary);
    font-size: 0.88rem;
    max-width: 520px;
    line-height: 1.5;
}

/* ==========================================================================
   Streamlit Native Form Controls & Button Overrides
   ========================================================================== */

/* Buttons */
.stButton button, .stDownloadButton button {
    background: linear-gradient(135deg, #00d2ff 0%, #3b82f6 100%) !important;
    color: #030a16 !important;
    border: 0 !important;
    border-radius: var(--r-md) !important;
    font-weight: 750 !important;
    font-size: 0.92rem !important;
    letter-spacing: 0.01em !important;
    min-height: 48px !important;
    padding: 0.7rem 1.4rem !important;
    box-shadow: 0 8px 20px rgba(0, 229, 255, 0.18) !important;
    transition: all 160ms cubic-bezier(0.4, 0, 0.2, 1) !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 0.5rem !important;
}

.stButton button:hover, .stDownloadButton button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 12px 28px rgba(0, 229, 255, 0.3) !important;
    filter: brightness(1.08) !important;
}

.stButton button:active, .stDownloadButton button:active {
    transform: translateY(0) !important;
}

[data-testid="stSidebar"] .stButton button {
    background: rgba(14, 27, 48, 0.9) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border-card) !important;
    box-shadow: none !important;
    min-height: 42px !important;
}

[data-testid="stSidebar"] .stButton button:hover {
    border-color: var(--accent-cyan) !important;
    background: rgba(20, 38, 68, 0.95) !important;
    color: var(--accent-cyan) !important;
}

/* Form Inputs */
.stTextInput div[data-baseweb="input"],
.stSelectbox div[data-baseweb="select"],
.stMultiSelect div[data-baseweb="select"],
.stTextArea textarea {
    background: rgba(10, 20, 36, 0.92) !important;
    border: 1px solid var(--border-card) !important;
    border-radius: var(--r-md) !important;
    min-height: 48px !important;
    color: var(--text-primary) !important;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.35) !important;
    transition: all 160ms ease !important;
}

.stTextInput input, .stSelectbox input, .stMultiSelect input {
    color: var(--text-primary) !important;
    padding: 0 1rem !important;
    font-size: 0.92rem !important;
}

.stTextInput input::placeholder, .stTextArea textarea::placeholder {
    color: var(--text-muted) !important;
}

.stTextInput div[data-baseweb="input"]:focus-within,
.stSelectbox div[data-baseweb="select"]:focus-within,
.stMultiSelect div[data-baseweb="select"]:focus-within,
.stTextArea textarea:focus {
    border-color: var(--accent-cyan) !important;
    box-shadow: 0 0 0 1px var(--accent-cyan), 0 0 16px rgba(0, 229, 255, 0.16) !important;
}

.stTextInput [data-testid="InputInstructions"] {
    display: none !important;
}

/* Labels */
.stTextInput label, .stSelectbox label, .stMultiSelect label, .stDateInput label, .stFileUploader label {
    color: var(--text-primary) !important;
    font-size: 0.86rem !important;
    font-weight: 700 !important;
    margin-bottom: 0.35rem !important;
}

/* MultiSelect Tags */
.stMultiSelect [data-baseweb="tag"] {
    background: rgba(0, 229, 255, 0.15) !important;
    border: 1px solid rgba(0, 229, 255, 0.32) !important;
    border-radius: var(--r-sm) !important;
    color: #e0f2fe !important;
}

/* File Uploader */
.stFileUploader section {
    background: rgba(10, 20, 36, 0.8) !important;
    border: 1px dashed var(--border-card) !important;
    border-radius: var(--r-md) !important;
    padding: 1.4rem !important;
    transition: border-color 160ms ease !important;
}

.stFileUploader section:hover {
    border-color: var(--accent-cyan) !important;
}

/* Dataframe Styling */
.stDataFrame, .stDataEditor {
    border: 1px solid var(--border-card) !important;
    border-radius: var(--r-md) !important;
    overflow: hidden !important;
}

/* Divider */
.soc-divider {
    height: 1px;
    width: 100%;
    background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.18), transparent);
    margin: 1.25rem 0;
}

/* ==========================================================================
   Responsive Breakpoints & Media Queries
   ========================================================================== */

@media (max-width: 1200px) {
    .soc-feature-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    .soc-scoreboard {
        grid-template-columns: repeat(3, 1fr);
    }
}

@media (max-width: 900px) {
    .soc-kpi-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    .soc-feature-grid {
        grid-template-columns: 1fr;
    }
    .soc-scoreboard {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 768px) {
    .block-container {
        padding-top: 0.8rem !important;
        padding-left: 0.9rem !important;
        padding-right: 0.9rem !important;
    }
    .soc-kpi-grid {
        grid-template-columns: 1fr;
    }
    .soc-scoreboard {
        grid-template-columns: 1fr;
    }
    .soc-hero-card {
        padding: 1.2rem;
    }
    .soc-hero-top {
        flex-direction: column;
        align-items: stretch;
    }
    .soc-hero-badges {
        justify-content: flex-start;
    }
    .soc-verdict-banner {
        flex-direction: column;
        align-items: flex-start;
    }
    .soc-verdict-score-box {
        text-align: left;
        margin-top: 0.5rem;
    }
}
</style>
"""


def apply_theme() -> None:
    """Inject the Enterprise Cyber SOC Design System CSS into the Streamlit app."""
    import streamlit as st
    st.markdown(SOC_CSS, unsafe_allow_html=True)


def chart_layout(
    fig: go.Figure,
    *,
    height: int = 360,
    title: str | None = None,
    legend: str = "h",
) -> go.Figure:
    """Format Plotly charts with the Enterprise Cyber SOC dark theme."""
    top_margin = 52 if (title or (fig.layout.title and fig.layout.title.text)) else 24
    fig.update_layout(
        template="plotly_dark",
        height=height,
        margin={"l": 24, "r": 24, "t": top_margin, "b": 24},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif", "color": "#f8fafc", "size": 12},
        legend=(
            {"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1, "font": {"size": 11, "color": "#94a3b8"}}
            if legend == "h"
            else {"orientation": "v", "font": {"size": 11, "color": "#94a3b8"}}
        ),
    )
    if title:
        fig.update_layout(
            title={"text": f"<b>{title}</b>", "x": 0.01, "xanchor": "left", "font": {"size": 14, "color": "#f8fafc"}}
        )
    elif fig.layout.title and fig.layout.title.text:
        fig.update_layout(
            title={"text": f"<b>{fig.layout.title.text}</b>", "x": 0.01, "xanchor": "left", "font": {"size": 14, "color": "#f8fafc"}}
        )

    fig.update_xaxes(
        gridcolor="rgba(148, 163, 184, 0.08)",
        zerolinecolor="rgba(148, 163, 184, 0.12)",
        tickfont={"color": "#94a3b8", "size": 11},
        title_font={"color": "#94a3b8", "size": 12},
        automargin=True,
    )
    fig.update_yaxes(
        gridcolor="rgba(148, 163, 184, 0.08)",
        zerolinecolor="rgba(148, 163, 184, 0.12)",
        tickfont={"color": "#94a3b8", "size": 11},
        title_font={"color": "#94a3b8", "size": 12},
        automargin=True,
    )

    hover_cfg = {
        "bgcolor": "#091322",
        "bordercolor": "rgba(0, 229, 255, 0.35)",
        "font": {"color": "#f8fafc", "family": "Inter, sans-serif"},
    }
    for tr in fig.data:
        ttype = getattr(tr, "type", "").lower()
        if ttype in {"scatter", "bar", "pie", "heatmap", "box", "violin", "histogram", "line"}:
            try:
                tr.update(hoverlabel=hover_cfg)
            except Exception:
                pass
    return fig


def dual_gauge(confidence: float, risk: float) -> go.Figure:
    """Render high-contrast, dual security gauges for model confidence and risk score."""
    def _indicator(value: float, title: str, domain_x: list[float], is_risk: bool = False) -> go.Indicator:
        bar_color = "#ef4444" if (is_risk and value > 0.7) else ("#f59e0b" if (is_risk and value > 0.45) else "#00e5ff")
        return go.Indicator(
            mode="gauge+number",
            value=round(value * 100, 1),
            number={"suffix": "%", "font": {"size": 28, "color": "#f8fafc", "family": "Inter, sans-serif"}},
            title={"text": f"<b>{title}</b>", "font": {"color": "#94a3b8", "size": 13, "family": "Inter, sans-serif"}},
            domain={"x": domain_x, "y": [0, 1]},
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 1,
                    "tickcolor": "#64748b",
                    "tickfont": {"size": 10, "color": "#94a3b8"},
                },
                "bar": {"color": bar_color, "thickness": 0.32},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 40], "color": "rgba(16, 185, 129, 0.16)"},
                    {"range": [40, 70], "color": "rgba(245, 158, 11, 0.16)"},
                    {"range": [70, 100], "color": "rgba(239, 68, 68, 0.18)"},
                ] if is_risk else [
                    {"range": [0, 50], "color": "rgba(100, 116, 139, 0.16)"},
                    {"range": [50, 80], "color": "rgba(59, 130, 246, 0.16)"},
                    {"range": [80, 100], "color": "rgba(0, 229, 255, 0.20)"},
                ],
            },
        )

    fig = go.Figure()
    fig.add_trace(_indicator(confidence, "Model Confidence", [0.0, 0.47], is_risk=False))
    fig.add_trace(_indicator(risk, "Hybrid Threat Score", [0.53, 1.0], is_risk=True))
    fig.update_layout(
        height=240,
        margin={"l": 20, "r": 20, "t": 42, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, sans-serif", "color": "#f8fafc"},
    )
    return fig
