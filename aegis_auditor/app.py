from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from .storage import AuditStorage
from .ui import MainWindow, apply_theme


def base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    root = Path.home() / ".aegis-auth-auditor"
    root.mkdir(parents=True, exist_ok=True)
    return root


def run() -> int:
    app = QApplication(sys.argv)
    apply_theme(app)
    storage = AuditStorage(data_dir() / "history.db")
    window = MainWindow(storage, base_dir() / "assets")
    window.show()
    return app.exec()
