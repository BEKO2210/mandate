"""Exact money. Amounts are integers in minor units, never floats.

A float cannot represent 0.10 or 0.20 exactly. Summing them and comparing
against a 0.30 cap decides wrongly. Every amount that reaches policy, budget
reservation or the ledger is converted here, once, exactly.

Wire format stays decimal (``"amount": 0.10``) so signatures and existing
clients keep working. The canonical JSON that is signed serialises a float via
``repr``, which is exactly what ``Decimal(str(value))`` reads back, so the
conversion is a faithful reading of the signed bytes.
"""

from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from typing import Any

# ISO 4217 minor-unit exponents that differ from the default of 2.
_EXPONENTS: dict[str, int] = {
    "BIF": 0, "CLP": 0, "DJF": 0, "GNF": 0, "ISK": 0, "JPY": 0, "KMF": 0,
    "KRW": 0, "PYG": 0, "RWF": 0, "UGX": 0, "VND": 0, "VUV": 0, "XAF": 0,
    "XOF": 0, "XPF": 0,
    "BHD": 3, "IQD": 3, "JOD": 3, "KWD": 3, "LYD": 3, "OMR": 3, "TND": 3,
}
DEFAULT_EXPONENT = 2

# Upper bound in major units, mirrored from the previous float validation.
MAX_MAJOR = Decimal(1_000_000_000)


class MoneyError(ValueError):
    pass


def exponent(currency: str) -> int:
    if not isinstance(currency, str):
        raise MoneyError("invalid currency")
    return _EXPONENTS.get(currency.upper(), DEFAULT_EXPONENT)


def _to_decimal(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise MoneyError("invalid amount")
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise MoneyError("invalid amount")
        # repr() of the float is what canonical JSON signed.
        return Decimal(str(value))
    if isinstance(value, str):
        try:
            return Decimal(value)
        except InvalidOperation as exc:
            raise MoneyError("invalid amount") from exc
    raise MoneyError("invalid amount")


def to_minor(value: Any, currency: str) -> int:
    """Convert a major-unit amount to integer minor units, or raise.

    Rejects anything that is not exactly representable in the currency, so
    0.001 EUR fails instead of being silently rounded into a budget.
    """
    d = _to_decimal(value)
    if not d.is_finite():
        raise MoneyError("invalid amount")
    if d < 0:
        raise MoneyError("negative amount")
    if d > MAX_MAJOR:
        raise MoneyError("amount out of range")
    scaled = d.scaleb(exponent(currency))
    if scaled != scaled.to_integral_value():
        raise MoneyError(f"amount {value} is finer than {currency} minor units")
    return int(scaled)


def from_minor(minor: int, currency: str) -> Decimal:
    """Exact major-unit value for display and reporting. Never for arithmetic."""
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise MoneyError("invalid minor amount")
    return Decimal(minor).scaleb(-exponent(currency))


def format_minor(minor: int, currency: str) -> str:
    exp = exponent(currency)
    return f"{from_minor(minor, currency):.{exp}f}"


def require_minor(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MoneyError("amount_minor must be an integer")
    if value < 0:
        raise MoneyError("negative amount_minor")
    return value
