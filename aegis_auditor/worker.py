from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .engine import AuditEngine
from .models import AuditResult


class AuditWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, target_url: str, login_url: str) -> None:
        super().__init__()
        self.target_url = target_url
        self.login_url = login_url

    @Slot()
    def run(self) -> None:
        try:
            result: AuditResult = AuditEngine().run(self.target_url, self.login_url)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
