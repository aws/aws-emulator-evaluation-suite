"""Where in a check a failure happened, independent of line numbers and run-specific values.

A behavioral check runs its ``run(ctx)`` statements in order, so the top-level statement a failure
surfaced in says how far the check got, and the innermost line of the check's own code says which
expectation or call failed. Both survive edits elsewhere in the file and re-randomized names.
"""

import ast
import functools
import traceback
from collections.abc import Callable
from types import FrameType
from typing import Any


@functools.lru_cache(maxsize=4096)
def _top_level_spans(filename: str, function: str) -> tuple[tuple[int, int], ...]:
    """``(first, last)`` line of each top-level statement of ``function`` in ``filename``."""
    try:
        with open(filename, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename)
    except (OSError, SyntaxError, ValueError):
        return ()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == function:
            return tuple((s.lineno, s.end_lineno or s.lineno) for s in node.body)
    return ()


def _statement(spans: tuple[tuple[int, int], ...], lineno: int) -> int | None:
    for i, (first, last) in enumerate(spans):
        if first <= lineno <= last:
            return i
    return None


def failure_site(exc: BaseException, fn: Callable) -> dict[str, Any] | None:
    """Where a failed check failed in its own file, else ``None``.

    Never raises: a site annotates a verdict and must not replace it.
    """
    try:
        return _failure_site(exc, fn)
    except Exception:  # a site is an annotation; it must never replace a verdict
        return None


def _aws_error(exc: BaseException) -> tuple[str, str, int | None]:
    """``(error code, operation, HTTP status)`` of ``exc`` or the exception it was raised from."""
    for candidate in (exc, exc.__cause__, exc.__context__):
        response = getattr(candidate, "response", None)
        error = response.get("Error") if isinstance(response, dict) else None
        if isinstance(error, dict) and error.get("Code"):
            status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
            operation = str(getattr(candidate, "operation_name", "") or "")
            return str(error["Code"]), operation, status if isinstance(status, int) else None
    return "", "", None


#: The ``exception`` of a check still running at its deadline.
TIMEOUT = "Timeout"


def timeout_site(frame: FrameType | None, fn: Callable) -> dict[str, Any] | None:
    """Where a check still running at its deadline was in its own file, else ``None``.

    ``frame`` is the check thread's current frame. Never raises, like :func:`failure_site`.
    """
    try:
        if frame is None:
            return None
        return _site(traceback.extract_stack(frame), fn, TIMEOUT, ("", "", None))
    except Exception:  # a site is an annotation; it must never replace a verdict
        return None


def _failure_site(exc: BaseException, fn: Callable) -> dict[str, Any] | None:
    return _site(traceback.extract_tb(exc.__traceback__), fn, type(exc).__name__, _aws_error(exc))


def _site(
    frames: list[traceback.FrameSummary],
    fn: Callable,
    exception: str,
    aws_error: tuple[str, str, int | None],
) -> dict[str, Any] | None:
    code = getattr(fn, "__code__", None)
    if code is None:
        return None
    own = [f for f in frames if f.filename == code.co_filename]
    if not own:
        return None
    innermost = own[-1]
    outer = next((f for f in own if f.name == code.co_name), None)
    spans = _top_level_spans(code.co_filename, code.co_name)
    return {
        "function": innermost.name,
        "source": " ".join((innermost.line or "").split()),
        "statement": _statement(spans, outer.lineno) if outer and outer.lineno else None,
        "exception": exception,
        "error_code": aws_error[0],
        "error_operation": aws_error[1],
        "error_status": aws_error[2],
    }
