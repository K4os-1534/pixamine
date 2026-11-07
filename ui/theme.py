"""Central theme module: the dark workbench design system.

Faithful Qt port of the pre-redesign Tkinter theme: warm graphite darks
(Catppuccin-family palette), a single cyan accent for interactive elements
and section tags, mono faces for hashes/offsets, uppercase tracked
micro-labels for section headers. All foreground/background pairs meet
WCAG 2.1 AA (verified: FG_FAINT 5.8:1, FG_MUTED 7.4:1, FG 11.3:1 on the
card/sunken backgrounds; accent pairs 6.0:1+).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Palette (exact values from the pre-redesign UI)
# ---------------------------------------------------------------------------
BG_WINDOW = "#11111b"
BG_CARD = "#1e1e2e"
BG_SUNKEN = "#181825"
BG_CONTROL = "#313244"
BG_CONTROL_HOVER = "#45475a"
BG_PRESSED = "#585b70"
FG = "#cdd6f4"
FG_MUTED = "#a6adc8"
FG_FAINT = "#9399b2"
ACCENT = "#06b6d4"
ACCENT_BRIGHT = "#67e8f9"   # selected-tab text (6.3:1 on BG_CONTROL_HOVER)
ACCENT_STRONG = "#0369a1"   # filled button bg / selection bg (white text 6.0:1)
ACCENT_HOVER = "#075985"
ACCENT_PRESSED = "#0c4a6e"
BORDER = "#45475a"
VIEWER_BG = "#0d0e15"

OK = "#4ade80"
INFO = "#60a5fa"
WARN = "#fbbf24"
CRIT = "#f87171"

SELECT_BG = ACCENT_STRONG
SELECT_FG = "#ffffff"

UI_FAMILIES = ["Noto Sans", "DejaVu Sans", "Segoe UI", "Helvetica Neue", "sans-serif"]
MONO_FAMILIES = ["Noto Mono", "DejaVu Sans Mono", "Consolas", "Menlo", "monospace"]

_fonts_resolved: tuple[str, str] | None = None


def resolve_fonts() -> tuple[str, str]:
    """Resolve concrete font families; must run after QApplication exists."""
    global _fonts_resolved
    if _fonts_resolved is None:
        from PySide6.QtGui import QFontDatabase
        try:
            families = set(QFontDatabase.families())
            ui = next((f for f in UI_FAMILIES if f in families), UI_FAMILIES[-1])
            mono = next((f for f in MONO_FAMILIES if f in families), MONO_FAMILIES[-1])
        except Exception:
            ui, mono = UI_FAMILIES[0], MONO_FAMILIES[0]
        _fonts_resolved = (ui, mono)
    return _fonts_resolved


# Pre-QApplication fallbacks; stylesheet() re-resolves against the real system.
UI_FONT, MONO_FONT = UI_FAMILIES[0], MONO_FAMILIES[0]


def stylesheet() -> str:
    """The full application QSS — the single source of visual truth."""
    global UI_FONT, MONO_FONT
    UI_FONT, MONO_FONT = resolve_fonts()
    return f"""
* {{
    font-family: "{UI_FONT}";
    font-size: 13px;
    outline: none;
}}
QMainWindow, QDialog {{
    background: {BG_WINDOW};
}}
QWidget {{
    background: {BG_WINDOW};
    color: {FG};
}}
QToolTip {{
    background: {BG_CARD};
    color: {FG};
    border: 1px solid {BORDER};
    padding: 6px 8px;
    font-size: 12px;
}}

/* --- labels ------------------------------------------------------------ */
QLabel[objectName="sectionLabel"] {{
    color: {ACCENT};
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
    background: transparent;
}}
QLabel[objectName="headingLabel"] {{
    color: {ACCENT};
    font-size: 14px;
    font-weight: 700;
    background: transparent;
}}
QLabel[objectName="valueLabel"] {{
    font-size: 16px;
    font-weight: 700;
    color: {FG};
    background: transparent;
}}
QLabel[objectName="monoLabel"] {{
    font-family: "{MONO_FONT}";
    font-size: 11px;
    color: {FG_FAINT};
    background: transparent;
}}
QLabel[objectName="mutedLabel"] {{
    color: {FG_MUTED};
    background: transparent;
}}
QLabel[objectName="scoreLabel"] {{
    font-family: "{MONO_FONT}";
    font-size: 32px;
    font-weight: 700;
    background: transparent;
}}
QLabel[objectName="readoutLabel"] {{
    font-family: "{MONO_FONT}";
    font-size: 11px;
    color: {FG_MUTED};
    background: {BG_CARD};
}}
QLabel[objectName="hintLabel"] {{
    color: {FG_FAINT};
    font-size: 12px;
    background: transparent;
}}
QLabel[objectName="caveatLabel"] {{
    color: {FG_FAINT};
    font-size: 12px;
    background: transparent;
}}

/* --- buttons ------------------------------------------------------------ */
QPushButton {{
    background: {BG_CONTROL};
    color: {FG};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 6px 14px;
}}
QPushButton:hover {{
    background: {BG_CONTROL_HOVER};
}}
QPushButton:pressed {{
    background: {BG_PRESSED};
}}
QPushButton:focus {{
    border: 1px solid {ACCENT};
}}
QPushButton:disabled {{
    color: {FG_FAINT};
    border-color: {BORDER};
    background: {BG_CARD};
}}
QPushButton[objectName="accentButton"] {{
    background: {ACCENT_STRONG};
    color: #ffffff;
    font-weight: 700;
    border: 1px solid {ACCENT_STRONG};
}}
QPushButton[objectName="accentButton"]:hover {{
    background: {ACCENT_HOVER};
}}
QPushButton[objectName="accentButton"]:pressed {{
    background: {ACCENT_PRESSED};
}}
QPushButton[objectName="smallButton"] {{
    padding: 4px 10px;
}}

/* --- inputs ------------------------------------------------------------ */
QLineEdit {{
    background: {BG_SUNKEN};
    color: {FG};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 4px 8px;
    selection-background-color: {SELECT_BG};
    selection-color: {SELECT_FG};
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QLineEdit:disabled {{ color: {FG_FAINT}; }}
QComboBox {{
    background: {BG_SUNKEN};
    color: {FG};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 4px 10px;
}}
QComboBox:disabled {{ color: {FG_FAINT}; }}
QComboBox:hover {{ border-color: {BG_CONTROL_HOVER}; }}
QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {BG_SUNKEN};
    color: {FG};
    border: 1px solid {BORDER};
    selection-background-color: {SELECT_BG};
    selection-color: {SELECT_FG};
}}
QCheckBox, QRadioButton {{
    color: {FG};
    spacing: 6px;
    background: transparent;
}}
QCheckBox:disabled, QRadioButton:disabled {{ color: {FG_FAINT}; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 13px; height: 13px;
    border: 1px solid {BORDER};
    background: {BG_SUNKEN};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; }}
QRadioButton::indicator {{ border-radius: 7px; }}
QRadioButton::indicator:checked {{
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.6, fx:0.5, fy:0.5,
        stop:0 {ACCENT}, stop:0.55 {ACCENT}, stop:0.6 {BG_SUNKEN});
}}

/* --- sliders ------------------------------------------------------------ */
QSlider::groove:horizontal {{
    height: 4px;
    background: {BG_SUNKEN};
    border: 1px solid {BORDER};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {ACCENT};
    width: 11px;
    margin: -5px 0;
    border-radius: 2px;
}}
QSlider::handle:horizontal:hover {{ background: {ACCENT_BRIGHT}; }}
QSlider::sub-page:horizontal {{ background: {ACCENT_STRONG}; }}
QSlider:disabled {{ background: transparent; }}

/* --- tables ------------------------------------------------------------ */
QTableView {{
    background: {BG_SUNKEN};
    alternate-background-color: {BG_SUNKEN};
    color: {FG};
    border: none;
    gridline-color: {BG_SUNKEN};
    selection-background-color: {SELECT_BG};
    selection-color: {SELECT_FG};
    font-size: 12px;
}}
QHeaderView::section {{
    background: {BG_SUNKEN};
    color: {FG_MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 5px 8px;
    font-size: 12px;
    font-weight: 700;
}}
QTableView QTableCornerButton::section {{
    background: {BG_SUNKEN};
    border: none;
}}

/* --- text editors ------------------------------------------------------ */
QPlainTextEdit {{
    background: {BG_SUNKEN};
    color: {FG};
    border: none;
    selection-background-color: {SELECT_BG};
    selection-color: {SELECT_FG};
    font-family: "{MONO_FONT}";
    font-size: 11px;
    padding: 4px 6px;
}}

/* --- tabs (notebook-block style) ---------------------------------------- */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    top: 0px;
}}
QTabBar::tab {{
    background: {BG_CONTROL};
    color: {FG};
    padding: 7px 16px;
    border: none;
    font-size: 12px;
}}
QTabBar::tab:hover {{ background: {BG_CONTROL_HOVER}; }}
QTabBar::tab:selected {{
    background: {BG_CONTROL_HOVER};
    color: {ACCENT_BRIGHT};
}}

/* --- splitters (paned window sashes) ------------------------------------ */
QSplitter::handle {{ background: {BG_SUNKEN}; }}
QSplitter::handle:horizontal {{ width: 4px; }}
QSplitter::handle:vertical {{ height: 4px; }}

/* --- cards (banner, gps bar, entropy box) ------------------------------- */
QFrame[objectName="card"] {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
}}
QLabel[objectName="cardMuted"] {{
    color: {FG_MUTED};
    background: {BG_CARD};
}}
QLabel[objectName="cardSection"] {{
    color: {ACCENT};
    background: {BG_CARD};
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
}}

/* --- scrollbars --------------------------------------------------------- */
QScrollBar:vertical {{
    background: {BG_WINDOW};
    width: 11px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BG_CONTROL};
    border-radius: 2px;
    min-height: 30px;
    margin: 2px 3px;
}}
QScrollBar::handle:vertical:hover {{ background: {BG_CONTROL_HOVER}; }}
QScrollBar:horizontal {{
    background: {BG_WINDOW};
    height: 11px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {BG_CONTROL};
    border-radius: 2px;
    min-width: 30px;
    margin: 3px 2px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* --- status bar --------------------------------------------------------- */
QStatusBar {{
    background: {BG_WINDOW};
    color: {FG_MUTED};
    font-size: 12px;
}}
QStatusBar::item {{ border: none; }}
"""
