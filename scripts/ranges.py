"""Version-range helpers.

A range is a plain string, which keeps the generated JSON small:
    "<= 1.2.3"        up to and including 1.2.3
    "< 5.8.3"         strictly below 5.8.3
    ">= 1.0, < 2.0"   lower and upper bound (a bound can be ">" or "<=" too)
    "= 1.5"           exactly 1.5
    "*"               all versions
"""
import re

EMPTY_VERSIONS = ("", "0", "0.0.0", "n/a", "*", "unspecified")
EXPR_RE = re.compile(r"^\s*(<=|>=|==|<|>|=)\s*(\S+)\s*$")


def mk_range(frm, frm_inc, to, to_inc):
    frm = "*" if frm is None or frm in EMPTY_VERSIONS else frm
    to = "*" if to is None or to in EMPTY_VERSIONS else to
    if frm == to and frm != "*" and frm_inc and to_inc:
        return f"= {frm}"
    parts = []
    if frm != "*":
        parts.append(f"{'>=' if frm_inc else '>'} {frm}")
    if to != "*":
        parts.append(f"{'<=' if to_inc else '<'} {to}")
    return ", ".join(parts) or "*"


def parse_version_expr(ver):
    """'< 5.8.3', '>= 6.4.0, < 6.4.3' -> range string; None if not an expression."""
    if not ver or not any(c in ver for c in "<>="):
        return None
    lo = hi = exact = None
    lo_inc = hi_inc = True
    for tok in ver.split(","):
        m = EXPR_RE.match(tok)
        if not m:
            return None
        op, v = m.groups()
        if op in (">", ">="):
            lo, lo_inc = v, op == ">="
        elif op in ("<", "<="):
            hi, hi_inc = v, op == "<="
        else:
            exact = v
    if exact is not None and lo is None and hi is None:
        return mk_range(exact, True, exact, True)
    return mk_range(lo, lo_inc, hi, hi_inc)


def cna_range(v):
    """Range from a CVE JSON 5 `versions[]` item."""
    ver = v.get("version", "")
    if "lessThanOrEqual" in v:
        return mk_range(ver, True, v["lessThanOrEqual"], True)
    if "lessThan" in v:
        return mk_range(ver, True, v["lessThan"], False)
    return parse_version_expr(ver) or mk_range(ver, True, ver, True)


def wf_range(r):
    """Range from a Wordfence `affected_versions` item."""
    return mk_range(r.get("from_version"), r.get("from_inclusive", True),
                    r.get("to_version"), r.get("to_inclusive", True))
