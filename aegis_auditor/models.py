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
