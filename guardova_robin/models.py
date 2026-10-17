"""Versioned, JSON-safe records for defensive watchlist collection.

An observed reference means that text was present on a fetched page. It is
never a statement that a breach occurred or that a claim on that page is true.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"


def validate_identifier(value: str, label: str) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > 128
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise ValueError("{} must be a nonempty identifier of at most 128 characters".format(label))
    return value


@dataclass(frozen=True)
class WatchTarget:
    watch_id: str
    tenant_id: str
    kind: str
    value: str

    def __post_init__(self):
        validate_identifier(self.watch_id, "watch_id")
        validate_identifier(self.tenant_id, "tenant_id")
        if self.kind not in ("domain", "email", "organization"):
            raise ValueError("kind must be domain, email or organization")
        if (not isinstance(self.value, str) or not self.value.strip()
                or len(self.value) > 320 or any(ord(ch) < 32 for ch in self.value)):
            raise ValueError("value must contain 1 to 320 printable characters")


@dataclass(frozen=True)
class CollectorLimits:
    max_results: int = 25
    max_pages: int = 10
    max_body_bytes: int = 1_000_000
    max_run_seconds: float = 120.0
    max_excerpt_chars: int = 300
    max_matches_per_page: int = 25

    def __post_init__(self):
        bounds = {"max_results": (1, 500), "max_pages": (1, 100),
                  "max_body_bytes": (256, 2_000_000), "max_excerpt_chars": (32, 1000),
                  "max_matches_per_page": (1, 100)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError("{} must be an integer from {} to {}".format(name, low, high))
        if (isinstance(self.max_run_seconds, bool)
                or not isinstance(self.max_run_seconds, (int, float))
                or not 0 < self.max_run_seconds <= 900):
            raise ValueError("max_run_seconds must be greater than 0 and at most 900")


@dataclass(frozen=True)
class ReferenceMatch:
    kind: str
    normalized_value: str
    matched_text: str
    start: int
    end: int


@dataclass
class Finding:
    finding_id: str
    tenant_id: str
    watch_id: str
    run_id: str
    source_url: str
    provenance: Dict[str, Any]
    fetched_at: str
    content_hash: str
    hash_scope: str
    excerpt: str
    matches: List[ReferenceMatch]
    status: str = "observed_reference"
    interpretation: str = "Textual reference observed; not proof of a breach."


@dataclass
class Coverage:
    scope: str = "search_engine_results_only"
    complete: bool = False
    search_status: str = "not_started"
    search_engines: List[Dict[str, Any]] = field(default_factory=list)
    results_received: int = 0
    results_considered: int = 0
    results_skipped: int = 0
    pages_attempted: int = 0
    pages_read: int = 0
    pages_failed: int = 0
    pages_without_matches: int = 0
    limits_reached: List[str] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    source_outcomes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class CollectionRun:
    run_id: str
    tenant_id: str
    watch_id: str
    target_kind: str
    normalized_target: str
    started_at: str
    completed_at: Optional[str] = None
    status: str = "running"
    coverage: Coverage = field(default_factory=Coverage)
    findings: List[Finding] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
