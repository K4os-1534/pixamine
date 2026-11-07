#!/usr/bin/env python3
"""Pixamine — image forensics workstation (Qt).

Usage:  python3 app.py [image]

All analysis lives in the analysis modules and pipeline.py; the GUI layer
is in ui/. There is no CLI: every feature is driven from the workstation.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    # The Wayland text-input plugin logs noisy protocol warnings on some
    # desktops; silence Qt's platform-plugin logging before Qt initializes.
    os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")

    from PySide6.QtWidgets import QApplication

    from ui import theme
    from ui.controller import AppController
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Pixamine")
    app.setStyleSheet(theme.stylesheet())

    controller = AppController()
    window = MainWindow(controller)
    window.show()

    initial_path = next((arg for arg in sys.argv[1:] if not arg.startswith("-")), None)
    if initial_path and os.path.isfile(initial_path):
        controller.load(initial_path)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
