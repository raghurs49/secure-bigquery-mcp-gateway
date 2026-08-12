"""Best-effort PII redaction applied to connector results before they reach the caller.

This is a defence-in-depth layer, not a substitute for querying pre-masked
reporting views (see docs/architecture.md's "why views are preferred"). It
catches PII that leaks through a column nobody flagged, at the cost of being
pattern-based and therefore imperfect.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

_REPLACEMENT = {
    "email": "[masked-email]",
    "phone": "[masked-phone]",
    "ssn": "[masked-ssn]",
    "card": "[masked-card]",
}


@dataclass
class MaskingReport:
    fields_masked: set[str] = field(default_factory=set)
    total_masks: int = 0

    def as_dict(self) -> dict:
        return {"fields_masked": sorted(self.fields_masked), "total_masks": self.total_masks}


def _mask_value(value: str) -> tuple[str, int]:
    masked = value
    count = 0
    for kind, pattern in _PATTERNS.items():
        masked, matches = pattern.subn(_REPLACEMENT[kind], masked)
        count += matches
    return masked, count


def mask_rows(rows: list[dict], *, enabled: bool) -> tuple[list[dict], MaskingReport]:
    """Returns a new list of rows with PII-shaped substrings redacted, plus a
    report of what changed. When `enabled` is False the rows pass through
    unchanged and the report is empty, so callers can log the setting either way."""

    report = MaskingReport()
    if not enabled:
        return rows, report

    masked_rows: list[dict] = []
    for row in rows:
        masked_row = {}
        for key, value in row.items():
            if isinstance(value, str):
                masked_value, count = _mask_value(value)
                masked_row[key] = masked_value
                if count:
                    report.fields_masked.add(key)
                    report.total_masks += count
            else:
                masked_row[key] = value
        masked_rows.append(masked_row)
    return masked_rows, report
