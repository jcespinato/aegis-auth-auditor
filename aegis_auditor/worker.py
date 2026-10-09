from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .active_auth import ActiveAuthEngine
from .engine import AuditEngine
from .models import ActiveAuthResult, AuditResult


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


class ActiveAuthWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, login_url: str, username: str, wrong_password: str, attempts: int, interval_seconds: float) -> None:
        super().__init__()
        self.login_url = login_url
        self.username = username
        self.wrong_password = wrong_password
        self.attempts = attempts
        self.interval_seconds = interval_seconds

    @Slot()
    def run(self) -> None:
        try:
            result: ActiveAuthResult = ActiveAuthEngine().run(self.login_url, self.username, self.wrong_password, self.attempts, self.interval_seconds)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
