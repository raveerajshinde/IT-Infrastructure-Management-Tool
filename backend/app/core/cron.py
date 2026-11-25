"""Minimal 5-field cron expressions (minute hour day-of-month month day-of-week), UTC.

Supports ``*``, ``*/n``, ``a``, ``a-b``, ``a-b/n`` and comma lists, plus the aliases
@hourly, @daily, @weekly and @monthly. Day-of-week: 0-7 (0 and 7 = Sunday), as in Vixie cron;
when both day fields are restricted a day matches if *either* matches.
"""
from __future__ import annotations

from datetime import datetime, timedelta

ALIASES = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *"}
RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
NAMES = ["minute", "hour", "day of month", "month", "day of week"]


class CronError(ValueError):
    pass


def _field(spec: str, lo: int, hi: int, name: str) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, st = part.split("/", 1)
            if not st.isdigit() or int(st) < 1:
                raise CronError(f"invalid step in {name}: '{st}'")
            step = int(st)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise CronError(f"invalid range in {name}: '{part}'")
            a, b = int(x), int(y)
        elif part.isdigit():
            a = b = int(part)
            if step > 1:
                b = hi
        else:
            raise CronError(f"invalid value in {name}: '{part}'")
        if a < lo or b > hi or a > b:
            raise CronError(f"{name} must be within {lo}-{hi}")
        out.update(range(a, b + 1, step))
    return out


class Cron:
    def __init__(self, expr: str):
        expr = ALIASES.get(expr.strip().lower(), expr.strip())
        parts = expr.split()
        if len(parts) != 5:
            raise CronError("cron needs 5 fields: minute hour day-of-month month day-of-week")
        self.expr = expr
        f = [_field(p, lo, hi, n) for p, (lo, hi), n in zip(parts, RANGES, NAMES)]
        self.minutes, self.hours, self.dom, self.months, dow = f
        self.dow = {d % 7 for d in dow}
        self.dom_any, self.dow_any = parts[2] == "*", parts[4] == "*"

    def _day_ok(self, t: datetime) -> bool:
        dom_ok = t.day in self.dom
        dow_ok = ((t.weekday() + 1) % 7) in self.dow  # python Monday=0 -> cron Monday=1
        if self.dom_any and self.dow_any:
            return True
        if self.dom_any:
            return dow_ok
        if self.dow_any:
            return dom_ok
        return dom_ok or dow_ok

    def next_after(self, after: datetime) -> datetime:
        t = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = after + timedelta(days=366 * 5)
        while t <= limit:
            if t.month not in self.months:
                t = (t.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
                continue
            if not self._day_ok(t):
                t = t.replace(hour=0, minute=0) + timedelta(days=1)
                continue
            if t.hour not in self.hours:
                t = t.replace(minute=0) + timedelta(hours=1)
                continue
            if t.minute not in self.minutes:
                t += timedelta(minutes=1)
                continue
            return t
        raise CronError("expression never matches (check day/month combination)")

    def describe(self) -> str:
        m, h, dom, mon, dow = self.expr.split()
        if (m, h, dom, mon, dow) == ("0", "*", "*", "*", "*"):
            return "Every hour"
        if m.isdigit() and h.isdigit():
            at = f"at {int(h):02d}:{int(m):02d} UTC"
            days = {"0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday", "4": "Thursday", "5": "Friday", "6": "Saturday", "7": "Sunday"}
            if dom == "*" and mon == "*" and dow == "*":
                return f"Daily {at}"
            if dom == "*" and mon == "*" and dow in days:
                return f"Every {days[dow]} {at}"
            if dom == "*" and mon == "*" and dow == "1-5":
                return f"Weekdays {at}"
            if dom.isdigit() and mon == "*" and dow == "*":
                return f"Monthly on day {dom} {at}"
        return f"cron '{self.expr}' (UTC)"
