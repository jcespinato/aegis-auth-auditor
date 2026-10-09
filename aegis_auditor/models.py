from dataclasses import dataclass, asdict
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
    summary: str
    findings: list[Finding]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data
