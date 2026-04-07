"""
calculator/logic.py — Pure Python financial calculator functions.

All functions raise ValueError on invalid inputs.
"""

from __future__ import annotations


def indian_format(num: float) -> str:
    """
    Format a number in Indian number system (e.g. 1,23,456.78).

    Raises TypeError if num is None.

    Args:
        num: A finite float or int. Must not be None.

    Returns:
        A string formatted with Indian-style comma grouping and 2 decimal places.
    """
    if num is None:
        raise TypeError("indian_format() requires a float, got None")
    negative = num < 0
    num = abs(round(num, 2))
    integer, decimal = f"{num:.2f}".split(".")
    if len(integer) > 3:
        last3 = integer[-3:]
        rest  = integer[:-3]
        parts: list[str] = []
        while len(rest) > 2:
            parts.insert(0, rest[-2:])
            rest = rest[:-2]
        if rest:
            parts.insert(0, rest)
        integer = ",".join(parts) + "," + last3
    return ("-" if negative else "") + integer + "." + decimal


def _positive(*args: float) -> None:
    for v in args:
        if v is None or v <= 0:
            raise ValueError(f"Value must be greater than zero (got {v!r})")


def calc_emi(loan: float, rate: float, years: int) -> dict:
    _positive(loan, rate, years)
    r     = rate / 100 / 12
    n     = years * 12
    emi   = loan * r * (1 + r) ** n / ((1 + r) ** n - 1)
    total = emi * n
    return {
        "emi":       round(emi, 2),
        "principal": round(loan, 2),
        "interest":  round(total - loan, 2),
        "total":     round(total, 2),
    }


def calc_sip(monthly: float, rate: float, years: int) -> dict:
    _positive(monthly, rate, years)
    r        = rate / 100 / 12
    n        = years * 12
    future   = monthly * ((1 + r) ** n - 1) / r * (1 + r)
    invested = monthly * n
    return {
        "invested": round(invested, 2),
        "returns":  round(future - invested, 2),
        "total":    round(future, 2),
    }


def calc_lumpsum(amount: float, rate: float, years: int) -> dict:
    _positive(amount, rate, years)
    total = amount * (1 + rate / 100) ** years
    return {
        "invested": round(amount, 2),
        "returns":  round(total - amount, 2),
        "total":    round(total, 2),
    }


def calc_fd(principal: float, rate: float, years: int) -> dict:
    """Fixed Deposit — quarterly compounding (standard Indian bank formula)."""
    _positive(principal, rate, years)
    total = principal * (1 + rate / 100 / 4) ** (4 * years)
    return {
        "invested": round(principal, 2),
        "returns":  round(total - principal, 2),
        "total":    round(total, 2),
    }


def calc_rd(deposit: float, rate: float, years: int) -> dict:
    """Recurring Deposit — quarterly compounding, month-by-month summation."""
    _positive(deposit, rate, years)
    qr           = (rate / 100) / 4
    total_months = years * 12
    maturity     = sum(
        deposit * (1 + qr) ** ((total_months - m + 1) / 3)
        for m in range(1, total_months + 1)
    )
    invested = deposit * total_months
    return {
        "invested": round(invested, 2),
        "returns":  round(maturity - invested, 2),
        "total":    round(maturity, 2),
    }


def calc_swp(
    principal: float, withdraw: float,
    rate: float, inflation: float, years: int,
) -> dict:
    """
    Systematic Withdrawal Plan with optional inflation adjustment.

    If withdraw >= principal on the first month, the corpus is depleted
    immediately: total_out equals principal, final_value is 0.

    Args:
        principal:  Starting corpus (> 0).
        withdraw:   Initial monthly withdrawal amount (> 0).
        rate:       Expected annual return rate in % (> 0).
        inflation:  Annual inflation rate applied to withdraw each month (>= 0).
        years:      Investment horizon in years (> 0).

    Raises:
        ValueError: If principal, withdraw, rate, or years are <= 0,
                    or if inflation is negative.
    """
    _positive(principal, withdraw, rate, years)
    if inflation < 0:
        raise ValueError("Inflation cannot be negative")

    mr  = rate / 100 / 12
    mir = inflation / 100 / 12
    bal, total_out, cur = principal, 0.0, withdraw

    for _ in range(years * 12):
        bal += bal * mr
        if bal <= 0:
            break
        if bal <= cur:
            # Corpus exhausted — pay out the remainder.
            total_out += bal
            bal = 0.0
            break
        bal       -= cur
        total_out += cur
        cur       *= (1 + mir)

    return {
        "investment":  round(principal, 2),
        "withdrawal":  round(total_out, 2),
        "final_value": round(bal, 2),
    }


def calc_weight(price_per_kg: float, grams: float) -> dict:
    """Price for a given weight in grams."""
    _positive(price_per_kg, grams)
    return {"price": round((price_per_kg / 1000) * grams, 2)}
