from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Finding:
    key: str
    title: str
    category: str
    status: str
    detail: str
    recommendation: str
    weight: int
    earned: int
    severity: str = "INFO"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    target_url: str
    login_url: str
    final_url: str
    started_at: str
    finished_at: str
    score: int
    risk: str
    coverage: int
    summary: str
    findings: list[Finding]
    metadata: dict[str, Any]
    category_scores: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data


@dataclass
class AttemptRecord:
    number: int
    status_code: int
    elapsed_ms: int
    signal: str
    retry_after: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActiveAuthResult:
    login_url: str
    account_hint: str
    started_at: str
    finished_at: str
    attempts_requested: int
    attempts_completed: int
    interval_seconds: float
    score: int
    risk: str
    verdict: str
    summary: str
    findings: list[Finding]
    attempts: list[AttemptRecord]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        data["attempts"] = [item.to_dict() for item in self.attempts]
        return data


@dataclass
class PasswordAnalysisResult:
    created_at: str
    score: int
    rating: str
    length: int
    entropy_bits: float
    search_space: str
    demo_found: bool
    demo_attempts: int
    demo_elapsed_ms: int
    summary: str
    findings: list[Finding]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data


@dataclass
class HashBenchmarkResult:
    created_at: str
    algorithm: str
    samples: int
    median_ms: float
    minimum_ms: float
    maximum_ms: float
    verifications_per_second: float
    rating: str
    summary: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LabAttemptRecord:
    number: int
    credential_kind: str
    status_code: int
    elapsed_ms: int
    signal: str
    success: bool
    retry_after: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LabSimulationResult:
    login_url: str
    account_hint: str
    started_at: str
    finished_at: str
    attempts_requested: int
    attempts_completed: int
    correct_attempt_number: int
    success_reached: bool
    protection_triggered: bool
    verdict: str
    risk: str
    summary: str
    findings: list[Finding]
    attempts: list[LabAttemptRecord]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        data["attempts"] = [item.to_dict() for item in self.attempts]
        return data
