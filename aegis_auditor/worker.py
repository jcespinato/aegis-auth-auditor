from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .active_auth import ActiveAuthEngine
from .engine import AuditEngine
from .hash_benchmark import HashBenchmark
from .lab_simulation import LabSimulationEngine
from .models import ActiveAuthResult, AuditResult, HashBenchmarkResult, LabSimulationResult, PasswordAnalysisResult
from .password_strength import PasswordAnalyzer


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


class PasswordWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, password: str) -> None:
        super().__init__()
        self.password = password

    @Slot()
    def run(self) -> None:
        try:
            result: PasswordAnalysisResult = PasswordAnalyzer().analyze(self.password)
            self.password = ""
            self.finished.emit(result)
        except Exception as exc:
            self.password = ""
            self.failed.emit(str(exc))


class HashWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, profile: str, samples: int) -> None:
        super().__init__()
        self.profile = profile
        self.samples = samples

    @Slot()
    def run(self) -> None:
        try:
            result: HashBenchmarkResult = HashBenchmark().run(self.profile, self.samples)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class LabWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, login_url: str, username: str, decoy_password: str, correct_password: str, attempts: int, correct_attempt: int, interval_seconds: float) -> None:
        super().__init__()
        self.login_url = login_url
        self.username = username
        self.decoy_password = decoy_password
        self.correct_password = correct_password
        self.attempts = attempts
        self.correct_attempt = correct_attempt
        self.interval_seconds = interval_seconds

    @Slot()
    def run(self) -> None:
        try:
            result: LabSimulationResult = LabSimulationEngine().run(self.login_url, self.username, self.decoy_password, self.correct_password, self.attempts, self.correct_attempt, self.interval_seconds)
            self.decoy_password = ""
            self.correct_password = ""
            self.finished.emit(result)
        except Exception as exc:
            self.decoy_password = ""
            self.correct_password = ""
            self.failed.emit(str(exc))
