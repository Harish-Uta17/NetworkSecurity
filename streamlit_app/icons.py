"""High-precision SVG icon library and helpers for PhishGuard AI SOC Dashboard."""

from __future__ import annotations
from typing import Optional


# SVG Path definitions (Lucide / Feather / Heroicon standard 24x24 viewBox)
SVG_PATHS = {
    "shield": """<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>""",
    "shield-check": """<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>""",
    "shield-alert": """<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>""",
    "radar": """<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.24"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>""",
    "activity": """<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>""",
    "zap": """<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>""",
    "compass": """<circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>""",
    "bar-chart": """<line x1="12" x2="12" y1="20" y2="10"/><line x1="18" x2="18" y1="20" y2="4"/><line x1="6" x2="6" y1="20" y2="16"/>""",
    "bar-chart-2": """<path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/>""",
    "pie-chart": """<path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>""",
    "layers": """<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>""",
    "cpu": """<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>""",
    "server": """<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>""",
    "hard-drive": """<line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/>""",
    "database": """<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/>""",
    "search": """<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>""",
    "alert-triangle": """<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/>""",
    "alert-octagon": """<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>""",
    "check-circle": """<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>""",
    "x-circle": """<circle cx="12" cy="12" r="10"/><line x1="15" x2="9" y1="9" y2="15"/><line x1="9" x2="15" y1="9" y2="15"/>""",
    "terminal": """<polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/>""",
    "file-text": """<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/>""",
    "upload-cloud": """<path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M12 12v9"/><path d="m16 16-4-4-4 4"/>""",
    "download": """<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>""",
    "filter": """<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>""",
    "clock": """<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>""",
    "refresh-cw": """<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>""",
    "info": """<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="16" y2="12"/><line x1="12" x2="12.01" y1="8" y2="8"/>""",
    "lock": """<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>""",
    "globe": """<circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>""",
    "fingerprint": """<path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>""",
    "trending-up": """<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>""",
    "crosshair": """<circle cx="12" cy="12" r="10"/><line x1="22" x2="18" y1="12" y2="12"/><line x1="6" x2="2" y1="12" y2="12"/><line x1="12" x2="12" y1="6" y2="2"/><line x1="12" x2="12" y1="22" y2="18"/>""",
    "target": """<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>""",
    "sliders": """<line x1="4" x2="4" y1="21" y2="14"/><line x1="4" x2="4" y1="10" y2="3"/><line x1="12" x2="12" y1="21" y2="12"/><line x1="12" x2="12" y1="8" y2="3"/><line x1="20" x2="20" y1="21" y2="16"/><line x1="20" x2="20" y1="12" y2="3"/><line x1="1" x2="7" y1="14" y2="14"/><line x1="9" x2="15" y1="8" y2="8"/><line x1="17" x2="23" y1="16" y2="16"/>""",
    "external-link": """<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/>""",
    "check": """<polyline points="20 6 9 17 4 12"/>""",
    "arrow-right": """<line x1="5" x2="19" y1="12" y2="12"/><polyline points="12 5 19 12 12 19"/>""",
    "flame": """<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>""",
    "sparkles": """<path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/>""",
}


def get_svg_icon(
    name: str,
    size: int = 24,
    color: Optional[str] = None,
    stroke_width: float = 2.0,
    class_name: str = "soc-icon",
) -> str:
    """Return raw SVG element string for the given icon name."""
    path_content = SVG_PATHS.get(name, SVG_PATHS["shield"])
    color_style = f"color: {color};" if color else ""
    return (
        f'<svg class="{class_name}" viewBox="0 0 24 24" width="{size}" height="{size}" '
        f'fill="none" stroke="currentColor" stroke-width="{stroke_width}" '
        f'stroke-linecap="round" stroke-linejoin="round" '
        f'style="{color_style} display: inline-block; vertical-align: middle; flex-shrink: 0;">'
        f'{path_content}'
        f'</svg>'
    )


def render_icon_box(
    name: str,
    tone: str = "cyan",
    size: str = "md",
    class_name: str = "",
) -> str:
    """
    Render an icon enclosed in a standardized, styled enterprise container.

    Sizes:
    - 'sm': 36px box, 18px icon
    - 'md': 48px box, 24px icon (default for stat cards)
    - 'lg': 54px box, 28px icon (feature cards)
    - 'xl': 64px box, 32px icon (hero / major verdicts)

    Tones: 'cyan', 'blue', 'indigo', 'emerald', 'amber', 'crimson', 'slate'
    """
    size_map = {
        "sm": (36, 18, 10),
        "md": (48, 24, 12),
        "lg": (54, 28, 14),
        "xl": (64, 32, 16),
    }
    box_size, icon_size, border_radius = size_map.get(size, (48, 24, 12))

    tone_classes = {
        "cyan": "tone-cyan",
        "blue": "tone-blue",
        "indigo": "tone-indigo",
        "emerald": "tone-emerald",
        "good": "tone-emerald",
        "safe": "tone-emerald",
        "amber": "tone-amber",
        "warn": "tone-amber",
        "suspicious": "tone-amber",
        "crimson": "tone-crimson",
        "danger": "tone-crimson",
        "phishing": "tone-crimson",
        "slate": "tone-slate",
        "neutral": "tone-slate",
    }
    tone_class = tone_classes.get(tone.lower(), "tone-cyan")
    extra_class = f" {class_name}" if class_name else ""

    svg = get_svg_icon(name, size=icon_size)
    return (
        f'<div class="soc-icon-box {tone_class} size-{size}{extra_class}" '
        f'style="width: {box_size}px; height: {box_size}px; border-radius: {border_radius}px;">'
        f'{svg}'
        f'</div>'
    )
