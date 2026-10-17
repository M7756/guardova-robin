"""Guardova's deterministic, source-backed Robin monitoring adapter."""

from .collector import collect_watch
from .matching import find_matches, normalize_domain, normalize_target
from .models import (SCHEMA_VERSION, CollectionRun, CollectorLimits, Coverage,
                     Finding, ReferenceMatch, WatchTarget)

__all__ = ["SCHEMA_VERSION", "CollectionRun", "CollectorLimits", "Coverage", "Finding",
           "ReferenceMatch", "WatchTarget", "collect_watch", "find_matches",
           "normalize_domain", "normalize_target"]
