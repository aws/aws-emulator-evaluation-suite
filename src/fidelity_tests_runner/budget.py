"""How long a fidelity test may run on an emulator, and the one retry rule for a timeout.

A test gets ``EMULATOR_MAX_BUDGET_S`` when it waits out an AWS-defined period (``timing:real-time``)
or requires a slow tool (``SLOW_TOOLS``) in its own ``require_tools(...)`` calls, else
``EMULATOR_BUDGET_S``. No manifest carries a budget.
"""

import argparse
import ast
import functools
import math
import re
from collections.abc import Iterable
from pathlib import Path

#: A test's budget on an emulator.
EMULATOR_BUDGET_S = 60.0
#: The budget of a real-time test or one that drives a slow tool; no test's budget exceeds it.
EMULATOR_MAX_BUDGET_S = 600.0
#: The binaries that make a test slow: IaC deploys and image builds.
SLOW_TOOLS = frozenset({"cdk", "terraform", "tofu", "docker"})
#: The budget of the one retry a timed-out test gets when a run retries timeouts.
RETRY_BUDGET_S = 180.0
#: A test whose graded step waits out an AWS-defined period (a TTL, a schedule, a metric period).
REAL_TIME_TAG = "timing:real-time"
#: The longest AWS-defined period a real-time test may wait out on an emulator.
REAL_TIME_MAX_PERIOD_S = EMULATOR_MAX_BUDGET_S - EMULATOR_BUDGET_S
#: The kinds of AWS-defined period a ``timing:real-time`` test waits out.
REAL_TIME_KINDS = frozenset(
    {
        "ttl",
        "schedule",
        "metric",
        "buffer",
        "cooldown",
        "lease",
        "visibility",
        "workflow",
        "retention",
    }
)
#: A real-time test's justification, one comment line above its ``@tags``:
#: ``# timing:real-time — <kind>: <N> s [AWS docs URL]``.
REAL_TIME_COMMENT_RE = re.compile(
    r"^\s*#\s*timing:real-time\s+—\s+(?P<kind>[a-z]+):\s+(?P<period_s>\d+)\s+s"
    r"(?:\s+(?P<url>https://\S+))?\s*$"
)


def is_positive_seconds(value: object) -> bool:
    """Whether ``value`` is a finite, positive int or float of seconds; a bool never is."""
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def require_positive_seconds(value: object, what: str) -> float:
    """``value`` as a float when it is positive seconds, else ``ValueError`` naming ``what``."""
    if not is_positive_seconds(value):
        raise ValueError(f"{what} must be a positive number of seconds, not {value!r}")
    return float(value)


def tools_in(tree: ast.AST) -> frozenset[str]:
    """The string literals passed to ``require_tools(...)`` anywhere in ``tree``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if called == "require_tools":
            names.update(
                a.value
                for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            )
    return frozenset(names)


def required_tools(source: str) -> frozenset[str]:
    """The binaries a test's source names in its ``require_tools(...)`` calls, read statically."""
    try:
        return tools_in(ast.parse(source))
    except SyntaxError:
        return frozenset()


@functools.cache
def required_tools_of_file(path: str) -> frozenset[str]:
    """``required_tools`` of the test file at ``path``; none when it cannot be read."""
    try:
        return required_tools(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return frozenset()


def check_budget(
    tags: Iterable[str], *, explicit: float | None = None, tools: Iterable[str] = ()
) -> float:
    """The test's budget, in seconds: the caller's ``explicit`` one, else the rule's."""
    if explicit is not None:
        return require_positive_seconds(explicit, "timeout_s")
    if REAL_TIME_TAG in frozenset(tags) or SLOW_TOOLS & frozenset(tools):
        return EMULATOR_MAX_BUDGET_S
    return EMULATOR_BUDGET_S


def positive_seconds(value: str) -> float:
    """Argparse type: a finite, positive number of seconds."""
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number of seconds") from None
    if not is_positive_seconds(seconds):
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive number of seconds")
    return seconds


def exceeds_emulator_cap(
    tags: Iterable[str], period_s: float | None, aws_s: float | None = None
) -> bool:
    """Whether a real-time test waits out a period longer than ``REAL_TIME_MAX_PERIOD_S``.

    ``period_s`` is the period its justification states (``stated_period_s``). Without one, its
    measured real-AWS run ``aws_s``, which bounds the period, stands in for it.
    """
    if REAL_TIME_TAG not in frozenset(tags):
        return False
    bound = period_s if period_s is not None else aws_s
    return bound is not None and bound > REAL_TIME_MAX_PERIOD_S


def real_time_comment(source: str) -> re.Match[str] | None:
    """The source's ``timing:real-time`` justification line, when it has a valid one."""
    for line in source.splitlines():
        match = REAL_TIME_COMMENT_RE.match(line)
        if match and match["kind"] in REAL_TIME_KINDS:
            return match
    return None


def stated_period_s(source: str) -> float | None:
    """The period, in seconds, that the source's ``timing:real-time`` justification states."""
    match = real_time_comment(source)
    return float(match["period_s"]) if match else None
