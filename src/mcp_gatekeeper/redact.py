"""Mask secrets and personal data in tool arguments before they are written anywhere.

Two passes run over every argument:

1. Keys: a value whose key looks like a secret (password, token, api_key, ...)
   is replaced whole, whatever it contains.
2. Values: strings are scanned for API keys, bearer tokens, private keys,
   JWTs, emails, phone numbers, IBANs (checked with mod-97) and card numbers
   (checked with Luhn). Checksums keep order numbers and amounts from being
   masked by mistake.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "authorization",
    "cookie",
    "sessionid",
    "cardnumber",
    "cvv",
    "cvc",
    "ssn",
)
SECRET_KEYS_EXACT = ("pin", "auth", "credentials")


def _normalise_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _iban_ok(candidate: str) -> bool:
    s = candidate.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _last4(s: str) -> str:
    return "".join(c for c in s if c.isalnum())[-4:]


# (label, regex, optional validator, keep last four characters)
_VALUE_RULES: list[tuple[str, re.Pattern[str], Any, bool]] = [
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
        None,
        False,
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), None, False),
    ("token", re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/-]{8,}=*"), None, False),
    (
        "api-key",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
            r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})"
        ),
        None,
        False,
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None, False),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), _iban_ok, True),
    ("card", re.compile(r"(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])"), _luhn_ok, True),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None, False),
    ("phone", re.compile(r"(?<![\w+])\+\d[\d -]{7,16}\d\b"), None, False),
]


@dataclass
class Redactor:
    """Masks arguments. Extra keys and regexes come from the policy's `redact` section."""

    extra_keys: Iterable[str] = ()
    extra_patterns: Iterable[str] = ()
    _keys: tuple[str, ...] = field(init=False)
    _patterns: list[re.Pattern[str]] = field(init=False)

    def __post_init__(self) -> None:
        self._keys = tuple(_normalise_key(k) for k in self.extra_keys)
        self._patterns = [re.compile(p) for p in self.extra_patterns]

    def key_is_secret(self, key: str) -> bool:
        k = _normalise_key(key)
        return k in SECRET_KEYS_EXACT or k in self._keys or any(part in k for part in SECRET_KEY_PARTS)

    def redact(self, value: Any) -> tuple[Any, list[str]]:
        """Return a masked copy of `value` and the sorted labels of what was masked."""
        found: set[str] = set()
        return self._walk(value, found), sorted(found)

    def _walk(self, value: Any, found: set[str]) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if isinstance(k, str) and self.key_is_secret(k) and v not in (None, ""):
                    found.add("secret-key")
                    out[k] = "[REDACTED]"
                else:
                    out[k] = self._walk(v, found)
            return out
        if isinstance(value, list):
            return [self._walk(v, found) for v in value]
        if isinstance(value, str):
            return self._text(value, found)
        if isinstance(value, int) and not isinstance(value, bool) and _luhn_ok(str(value)):
            found.add("card")
            return f"[REDACTED:card …{str(value)[-4:]}]"
        return value

    def _text(self, text: str, found: set[str]) -> str:
        for label, pattern, validator, keep in _VALUE_RULES:

            def replace(m: re.Match[str], label: str = label, validator: Any = validator, keep: bool = keep) -> str:
                if validator is not None and not validator(m.group(0)):
                    return m.group(0)
                found.add(label)
                return f"[REDACTED:{label} …{_last4(m.group(0))}]" if keep else f"[REDACTED:{label}]"

            text = pattern.sub(replace, text)
        for pattern in self._patterns:
            text, n = pattern.subn("[REDACTED:custom]", text)
            if n:
                found.add("custom")
        return text
