"""Deterministic identifier matching, without an LLM or a relevance filter."""

import re
import unicodedata
from typing import List

import idna

from .models import ReferenceMatch, WatchTarget

_DOTS = ".。．｡"
_MAIL_PUNCTUATION = ".!#$%&'*+/=?^`{|}~_@-"


def normalize_domain(value: str) -> str:
    """Accept a host, including IDNs, rather than URLs, paths or wildcards.

    The same IDNA 2008 / UTS 46 nontransitional policy applies to watch values
    and source tokens. In particular ß and Greek final sigma remain distinct.
    """
    if not isinstance(value, str):
        raise ValueError("invalid domain")
    value = value.strip().rstrip(_DOTS)
    try:
        domain = idna.encode(value, uts46=True, transitional=False, std3_rules=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError("invalid domain") from exc
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or labels[-1].isdigit():
        raise ValueError("invalid domain")
    return domain


def normalize_target(target: WatchTarget) -> str:
    if target.kind == "domain":
        return normalize_domain(target.value)
    if target.kind == "email":
        if target.value.count("@") != 1:
            raise ValueError("invalid email address")
        local, domain = target.value.strip().rsplit("@", 1)
        # Casefolding mailbox local parts could merge distinct addresses. We
        # preserve the local part and compare it exactly; the host ignores case.
        if (not local or len(local.encode("utf-8")) > 64 or local.startswith(".")
                or local.endswith(".") or ".." in local
                or not re.fullmatch(r"[\w.!#$%&'*+/=?^`{|}~-]+", local, re.UNICODE)):
            raise ValueError("unsupported email address")
        return unicodedata.normalize("NFC", local) + "@" + normalize_domain(domain)
    normalized = " ".join(unicodedata.normalize("NFC", target.value).casefold().split())
    if not any(ch.isalnum() for ch in normalized) or len(normalized) < 2:
        raise ValueError("organization must contain at least two characters and a letter or digit")
    return normalized


def _fold_with_offsets(text):
    """Casefold while retaining offsets into original evidence text."""
    pieces, origins = [], []
    for index, char in enumerate(text):
        folded = char.casefold()
        pieces.append(folded)
        origins.extend([index] * len(folded))
    return "".join(pieces), origins


def _word_component(char):
    category = unicodedata.category(char)
    return (char.isalnum() or char in "_-" or category.startswith("M")
            or category in ("Cn", "Co", "Cs") or char == "\ufffd")


def _identifier_spans(text, email=False):
    """Read complete Unicode tokens before normalizing DNS separators.

    Combining marks and all IDNA dot spellings belong to the token. A regex
    that recognizes only ASCII dots can incorrectly take example.com out of
    example.com。evil or 例。example.com and report an exact match.
    """
    punctuation = _MAIL_PUNCTUATION + _DOTS if email else "+-_" + _DOTS
    start = None
    for index, char in enumerate(text):
        included = _word_component(char) or char in punctuation
        if included and start is None:
            start = index
        elif not included and start is not None:
            yield start, index
            start = None
    if start is not None:
        yield start, len(text)


def find_matches(text: str, target: WatchTarget, limit: int = 25) -> List[ReferenceMatch]:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    normalized = normalize_target(target)
    found = []
    if target.kind == "organization":
        folded, origins = _fold_with_offsets(text)
        words = normalized.split()
        pattern = re.compile(r"\s+".join(re.escape(w) for w in words))
        spans = ((origins[m.start()], origins[m.end() - 1] + 1)
                 for m in pattern.finditer(folded)
                 if (m.start() == 0 or not _word_component(folded[m.start() - 1]))
                 and (m.end() == len(folded) or not _word_component(folded[m.end()])))
    else:
        def accepted_spans():
            for start, end in _identifier_spans(text, email=target.kind == "email"):
                value = text[start:end].rstrip(_DOTS)
                if len(value) > 320 or not any(dot in value for dot in _DOTS):
                    continue
                try:
                    if target.kind == "email":
                        if value.count("@") != 1:
                            continue
                        local, host = value.rsplit("@", 1)
                        candidate = unicodedata.normalize("NFC", local) + "@" + normalize_domain(host)
                    else:
                        candidate = normalize_domain(value)
                    if candidate == normalized:
                        yield start, start + len(value)
                except (ValueError, UnicodeError):
                    continue
        spans = accepted_spans()
    for start, end in spans:
        found.append(ReferenceMatch(target.kind, normalized, text[start:end], start, end))
        if len(found) >= limit:
            break
    return found


def minimized_excerpt(matches: List[ReferenceMatch], max_chars: int) -> str:
    """Keep reference text only: adjacent leaked credentials are never stored."""
    references = list(dict.fromkeys(match.matched_text for match in matches))
    text = " [context omitted] ".join(references)
    return text if len(text) <= max_chars else text[:max_chars - 1] + "…"
