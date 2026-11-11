"""Load one check file and run it against an emulator: verdict, site, teardown and report."""

import ast
import functools
import importlib
import importlib.util
import inspect
import json
import logging
import sys
import threading
import time
import traceback
import types
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any

from fidelity_tests_runner import isolate, verdicts
from fidelity_tests_runner.budget import (
    RETRY_BUDGET_S,
    check_budget,
    require_positive_seconds,
    required_tools_of_file,
)
from fidelity_tests_runner.context import Context
from fidelity_tests_runner.harness import (
    DEFAULT_CLEANUP_TIMEOUT_S,
    VERDICT_ERROR,
    VERDICT_FAILED,
    VERDICT_PASSED,
    CheckResult,
    scrub_paths,
    tags,
)
from fidelity_tests_runner.prerequisites import prepare_check
from fidelity_tests_runner.site import failure_site, timeout_site
from fidelity_tests_runner.target import NonLocalHostRefused
from fidelity_tests_runner.trust import emulator_tls
from fidelity_tests_runner.verdicts import (
    FAULT_RUNNER,
    FAULT_SETUP,
    is_not_up,
    missing_tools_of,
    runner_fault_of,
)

logger = logging.getLogger("fidelity_tests_runner.run")

#: The schema of the report ``run_file`` returns.
REPORT_SCHEMA = "fidelity-tests-runner/report/v1"


@dataclass(frozen=True)
class LoadedCheck:
    """One check file's ``CHECK``, ``GROUP`` and ``run``."""

    name: str
    group: str
    run: Callable[[Context], None]


def status_label(result: CheckResult) -> str:
    """The one-word console status; NOT-UP is an ERROR where nothing was listening."""
    return {
        VERDICT_PASSED: "PASS",
        VERDICT_FAILED: "FAILED",
        VERDICT_ERROR: "NOT-UP" if result.not_up else "ERROR",
    }[result.verdict]


def _register_behavioral_harness() -> None:
    """Make ``from behavioral_harness import tags`` resolve, synthesizing the module if absent."""
    try:
        importlib.import_module("behavioral_harness")
    except ModuleNotFoundError:
        module = types.ModuleType("behavioral_harness")
        module.tags = tags
        sys.modules["behavioral_harness"] = module


def loaded_from(run: Callable[[Context], None]) -> tuple[Path, LoadedCheck]:
    """The file ``run`` was defined in and its ``LoadedCheck``, as :func:`load_check` reads them."""
    g = getattr(run, "__globals__", {})
    path = Path(g.get("__file__") or run.__code__.co_filename).resolve()
    return path, LoadedCheck(
        name=str(g.get("CHECK", path.stem)), group=str(g.get("GROUP", "")), run=run
    )


def load_check(path: str | Path) -> LoadedCheck:
    """Import a ``check_<name>.py`` file under a unique module name and return its entrypoint.

    Importing runs the check module's top level, so callers load it isolated.
    Raises ``ValueError`` for a file without ``run``.
    """
    path = Path(path).resolve()
    _register_behavioral_harness()
    name = f"_fidelity_test_{path.stem}_{uuid.uuid4().hex[:8]}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    run = getattr(module, "run", None)
    if not callable(run):
        raise ValueError(f"{path} has no run(ctx) entrypoint")
    return LoadedCheck(
        name=str(getattr(module, "CHECK", path.stem)),
        group=str(getattr(module, "GROUP", "")),
        run=run,
    )


def _on_daemon_thread(
    fn: Callable[[], None], name: str, timeout_s: float
) -> tuple[bool, BaseException | None, FrameType | None]:
    """Run ``fn`` on a daemon thread for at most ``timeout_s``: ``(finished, exception, frame)``.

    A running call cannot be cancelled, so a timeout is the thread still alive at the deadline
    (``frame`` is where it was).
    """
    box: dict[str, BaseException | None] = {}

    def invoke() -> None:
        try:
            fn()
            box["exc"] = None
        except BaseException as exc:  # classified by the caller
            box["exc"] = exc

    thread = threading.Thread(target=invoke, name=name, daemon=True)
    thread.start()
    thread.join(timeout_s)
    if not thread.is_alive():
        return True, box.get("exc"), None
    return False, None, sys._current_frames().get(thread.ident or 0)


class _Once:
    """``fn`` run at most once, by whichever thread calls it first, and how that run ended."""

    def __init__(self, fn: Callable[[], None]) -> None:
        self._fn = fn
        self._claimed = threading.Lock()
        self._done = threading.Event()
        self.error: BaseException | None = None

    def __call__(self) -> None:
        if self._claimed.acquire(blocking=False):
            self._run()

    def _run(self) -> None:
        try:
            self._fn()
        except BaseException as exc:
            self.error = exc
            raise
        finally:
            self._done.set()

    @property
    def claimed(self) -> bool:
        return self._claimed.locked()

    def run_or_wait(self) -> None:
        """Run ``fn``, or wait for the thread that claimed it and raise what it raised."""
        if self._claimed.acquire(blocking=False):
            self._run()
            return
        self._done.wait()
        if self.error is not None:
            raise self.error


def _run_cleanups(
    ctx: Context, name: str, timeout_s: float, prepared: _Once | None = None
) -> tuple[float, str, bool]:
    """Run a test's teardown under a deadline: ``(elapsed ms, problem or "", failed)``.

    ``prepared`` (what the test's tags set up) is the last of its teardowns. When they do not
    finish in time, or never reach it, it gets another ``timeout_s``: it runs then, or, when the
    timed-out teardown already started it, this waits for that run. Either way its outcome is on
    the result. On the thread running each of the two, ``ctx.time_left()`` counts down its
    ``timeout_s``; a timed-out body still sees its own.
    """

    def budgeted(fn: Callable[[], None]) -> Callable[[], None]:
        def run() -> None:
            _start_deadline(ctx, timeout_s, this_thread=True)
            fn()

        return run

    elapsed, problem, failed, finished = _teardown(budgeted(ctx.run_cleanups), name, timeout_s)
    if prepared is None or (finished and prepared.claimed):
        return elapsed, problem, failed  # it ran inside the finished teardown, failure included
    more_ms, more, more_failed, _ = _teardown(budgeted(prepared.run_or_wait), name, timeout_s)
    note = f"the tags' setup teardown ran after the test's: {more}" if more else ""
    return (
        round(elapsed + more_ms, 1),
        "; ".join(filter(None, [problem, note])),
        (failed or more_failed),
    )


def _start_deadline(ctx: Context, budget_s: float, *, this_thread: bool = False) -> None:
    """``ctx.start_deadline`` when ``ctx`` keeps a budget for ``time_left()``.

    A context whose ``start_deadline`` takes no ``this_thread`` keeps one budget for the test: its
    teardown thread then starts none of its own.
    """
    start = getattr(ctx, "start_deadline", None)
    if not callable(start):
        return
    if not this_thread:
        start(budget_s)
    elif _takes_keyword(start, "this_thread"):
        start(budget_s, this_thread=True)


def _takes_keyword(fn: Callable[..., Any], name: str) -> bool:
    """Whether ``fn`` accepts the keyword argument ``name``."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == name or p.kind is inspect.Parameter.VAR_KEYWORD for p in params)


def _teardown(fn: Callable[[], None], name: str, timeout_s: float) -> tuple[float, str, bool, bool]:
    """``fn`` on a daemon thread under ``timeout_s``: ``(elapsed ms, problem, failed, finished)``.

    ``finished`` is False when ``fn`` was still running at the deadline.
    """
    started = time.perf_counter()
    finished, exc, _ = _on_daemon_thread(fn, f"cleanup:{name}", timeout_s)
    if not finished:
        problem = f"cleanup did not finish within {timeout_s}s — resources may leak"
    else:
        problem = scrub_paths(f"cleanup failed: {exc!r}") if exc is not None else ""
    failed = not finished or exc is not None
    return round((time.perf_counter() - started) * 1000.0, 1), problem, failed, finished


def _failure_detail(exc: BaseException, prefix: str = "") -> str:
    """The last three traceback frames with paths scrubbed, so a detail is portable."""
    frames = traceback.format_exception(type(exc), exc, exc.__traceback__)
    return scrub_paths(prefix + "".join(frames[-3:]).strip())


def _target_answered(exc: BaseException) -> bool:
    """``exc`` carries an AWS error response: the target answered."""
    response = getattr(exc, "response", None)
    return isinstance(response, dict) and isinstance(response.get("Error"), dict)


def _tools_of(fn: Callable) -> frozenset[str]:
    """The binaries ``fn``'s test file requires, read from its source."""
    path = getattr(getattr(fn, "__code__", None), "co_filename", "")
    return required_tools_of_file(path) if path else frozenset()


def run_check(
    ctx_factory: Callable[[], Context],
    name: str,
    group: str,
    fn: Callable[[Context], None],
    *,
    timeout_s: float | None = None,
    cleanup_timeout_s: float = DEFAULT_CLEANUP_TIMEOUT_S,
    service: str = "",
) -> CheckResult:
    """Run one ``run(ctx)`` on a fresh Context under its budget, then its teardown.

    An ``AssertionError`` or a timeout is FAILED, anything else an ERROR;
    ``fidelity_tests_runner.verdicts`` classifies it. What the test's tags set up before it
    (``prerequisites.prepare_check``) is torn down last, with its other teardowns.
    """
    clock = {"started": time.perf_counter()}
    target: dict[str, Any] = {"endpoint": ""}

    def result(
        passed: bool,
        detail: str | None,
        verdict: str,
        *,
        exc: BaseException | None = None,
        setup: bool = False,
        **extra: Any,
    ) -> CheckResult:
        fault, tools, not_up = extra.pop("runner_fault", ""), (), False
        if exc is not None and verdict == VERDICT_ERROR:
            tools = missing_tools_of(exc)
            fault = fault or ("" if tools else runner_fault_of(exc))
            if not (tools or fault):
                not_up = bool(target["endpoint"]) and is_not_up(exc, target["endpoint"])
                if setup and not not_up and not _target_answered(exc):
                    fault = FAULT_SETUP
        return CheckResult(
            name=name,
            group=group,
            passed=passed,
            detail=detail,
            duration_ms=extra.pop(
                "duration_ms", round((time.perf_counter() - clock["started"]) * 1000.0, 1)
            ),
            verdict=verdict,
            not_up=not_up and not fault,
            operation=name,
            service=service,
            runner_fault=fault,
            tool_missing=tuple(tools),
            **extra,
        )

    try:
        ctx = ctx_factory()
    except Exception as exc:  # nothing was observed
        return result(
            False,
            _failure_detail(exc, "context setup failed:\n"),
            VERDICT_ERROR,
            runner_fault=FAULT_SETUP,
        )
    target["endpoint"] = str(getattr(ctx, "_endpoint", "") or "")

    check_tags = tuple(getattr(fn, "__fidelity_test_tags__", ()))
    budget = check_budget(check_tags, explicit=timeout_s, tools=_tools_of(fn))
    try:
        prepared = prepare_check(
            check_tags, lambda svc: ctx.client(svc), unique_name=getattr(ctx, "unique_name", None)
        )
        prepared.__enter__()
    except (Exception, NonLocalHostRefused) as exc:  # the check never ran
        return result(
            False,
            _failure_detail(exc, "account setup failed:\n"),
            VERDICT_ERROR,
            exc=exc,
            setup=True,
            site=failure_site(exc, fn),
            budget_s=budget,
        )
    # Registered first, so it runs last: the test's own teardowns may need what it set up.
    release = _Once(lambda: prepared.__exit__(None, None, None))
    ctx.on_cleanup(release)
    clock["started"] = time.perf_counter()  # the measurement is the check's, not its setup

    def failed(exc: BaseException, **extra: Any) -> CheckResult:
        """A runner failure graded through ``result``."""
        graded = _runner_failure(name, group, service, exc)
        try:
            return result(False, graded.detail, VERDICT_ERROR, runner_fault=FAULT_RUNNER, **extra)
        except Exception:  # result() itself failed: grade without it
            return graded

    return _run_body(ctx, name, fn, result, failed, budget, cleanup_timeout_s, prepared=release)


def _run_body(
    ctx: Context,
    name: str,
    fn: Callable[[Context], None],
    result: Callable[..., CheckResult],
    failed: Callable[..., CheckResult],
    timeout_s: float,
    cleanup_timeout_s: float,
    *,
    prepared: _Once | None = None,
) -> CheckResult:
    """``run_check`` once the account is prepared: the body under its deadline, then teardown.

    Teardown, ``prepared`` last, runs once on every path and its outcome is on the result; a
    runner failure (no thread, a grading error) is ``failed``'s result, an interrupt is re-raised
    after teardown.
    """
    finished = True
    cleanup: tuple[float, str, bool] | None = None
    started = time.perf_counter()
    try:
        _start_deadline(ctx, timeout_s)
        finished, exc, frame = _on_daemon_thread(lambda: fn(ctx), f"check:{name}", timeout_s)
        if not finished:
            outcome = (False, f"Check timed out after {timeout_s}s", VERDICT_FAILED)
        elif exc is None:
            outcome = (True, None, VERDICT_PASSED)
        elif isinstance(exc, AssertionError):
            outcome = (False, _failure_detail(exc), VERDICT_FAILED)
        else:
            outcome = (False, _failure_detail(exc), VERDICT_ERROR)
        elapsed = round((time.perf_counter() - started) * 1000.0, 1)
        cleanup = _run_cleanups(ctx, name, cleanup_timeout_s, prepared)
        checked = result(
            *outcome,
            exc=exc,
            duration_ms=elapsed,
            site=failure_site(exc, fn) if exc is not None else timeout_site(frame, fn),
            timed_out=not finished,
            budget_s=timeout_s,
            published_url_violations=tuple(getattr(ctx, "published_url_violations", ())),
        )
    except BaseException as runner_exc:  # graded below or re-raised
        if cleanup is None:
            cleanup = _run_cleanups(ctx, name, cleanup_timeout_s, prepared)
        if isinstance(runner_exc, (KeyboardInterrupt, SystemExit)):
            logger.warning("%s interrupted; teardown: %s", name, cleanup[1] or "finished")
            raise
        checked = failed(runner_exc, budget_s=timeout_s, timed_out=not finished)
    checked.cleanup_ms, cleanup_detail, checked.cleanup_failed = cleanup
    if not finished:
        # The body cannot be cancelled, so teardown races it; what it creates afterwards remains.
        cleanup_detail = "; ".join(
            filter(
                None, [cleanup_detail, "teardown ran while the timed-out test was still running"]
            )
        )
    checked.cleanup_detail = cleanup_detail
    return checked


def check_entry(r: CheckResult) -> dict[str, Any]:
    """One test's result as the report's ``check`` object.

    ``verdict`` is passed, failed or error; ``kind`` the finer outcome ``summarize`` scores
    (``verdicts.SCORED_KINDS`` count, ``verdicts.EXCLUDED_KINDS`` do not). Optional fields appear
    only when they carry something.
    """
    entry: dict[str, Any] = {
        "check_id": r.check_id or (f"{r.service}.{r.name}" if r.service else r.name),
        "service": r.service,
        "verdict": r.verdict,
        "kind": verdicts.classify(r),
        "duration_ms": r.duration_ms,
        "detail": r.detail,
    }
    if r.budget_s:
        entry["budget_s"] = r.budget_s
    if r.site:
        entry["site"] = r.site
    if r.tool_missing:
        entry["tool_missing"] = list(r.tool_missing)
    if r.retried_after_timeout:
        entry["retried_after_timeout"] = True
    if r.published_url_violations:
        entry["published_url_violations"] = list(r.published_url_violations)
    if r.cleanup_failed or r.cleanup_detail:
        entry |= {
            "cleanup_failed": r.cleanup_failed,
            "cleanup_ms": r.cleanup_ms,
            "cleanup_detail": r.cleanup_detail,
        }
    return entry


#: The suite's index of its tests, at its root beside ``behavioral/``.
MANIFEST = "manifest.jsonl"


@functools.cache
def _manifest_ids(manifest: Path) -> dict[str, str]:
    """``{path: check_id}`` of every row of ``manifest``; ``{}`` when it cannot be read."""
    ids: dict[str, str] = {}
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ids
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("path"), str):
            if isinstance(row.get("check_id"), str):
                ids[row["path"]] = row["check_id"]
    return ids


def manifest_check_id(path: str | Path) -> str:
    """The ID the suite's manifest gives the test file at ``path``, or ``""`` outside a suite.

    A test keeps its ID when its file moves to another directory, so the ID is read from the
    manifest, never derived from the directory. Only the suite root of
    ``<root>/behavioral/<service>/check_x.py`` is read, never a manifest further up.
    """
    path = Path(path).resolve()
    if len(path.parents) < 3 or path.parents[1].name != "behavioral":
        return ""
    root = path.parents[2]
    manifest = root / MANIFEST
    if not manifest.is_file():
        return ""
    return _manifest_ids(manifest).get(path.relative_to(root).as_posix(), "")


def _source_constants(path: Path) -> tuple[str, str]:
    """``(CHECK, GROUP)`` as a check file's source spells them, else its stem and ``""``."""
    name, group = path.stem, ""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return name, group
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target, value = node.targets[0], node.value
        if isinstance(target, ast.Name) and isinstance(value, ast.Constant):
            if target.id == "CHECK" and isinstance(value.value, str):
                name = value.value
            elif target.id == "GROUP" and isinstance(value.value, str):
                group = value.value
    return name, group


def _unloadable_result(path: Path, service: str, exc: BaseException) -> CheckResult:
    """A check file that cannot be imported: kind ``unloadable``, never a finding."""
    name, group = _source_constants(path)
    return CheckResult(
        name=name,
        group=group,
        passed=False,
        detail=_failure_detail(exc, f"fidelity test {path.name} did not load:\n"),
        duration_ms=0.0,
        verdict=VERDICT_ERROR,
        operation=name,
        service=service,
        unloadable=True,
    )


def _runner_failure(name: str, group: str, service: str, exc: BaseException) -> CheckResult:
    """The runner itself raised (no thread could start): a runner fault."""
    return CheckResult(
        name=name,
        group=group,
        passed=False,
        detail=_failure_detail(exc, "runner failed:\n"),
        duration_ms=0.0,
        verdict=VERDICT_ERROR,
        operation=name,
        service=service,
        runner_fault=FAULT_RUNNER,
    )


def run_file(
    path: str | Path,
    ctx_factory: Callable[[], Context],
    *,
    endpoint: str,
    verify_ssl: bool | str = True,
    timeout_s: float | None = None,
    cleanup_timeout_s: float = DEFAULT_CLEANUP_TIMEOUT_S,
    retry_timeouts: bool = False,
    run_config: Mapping[str, Any] | None = None,
    check: LoadedCheck | None = None,
) -> tuple[CheckResult, dict[str, Any]]:
    """Load and run one check file, isolated: ``(result, report)``.

    The result's service is the file's directory (``<service>/check_x.py``) and its ID the
    suite manifest's (``manifest_check_id``). The budget is
    ``timeout_s``, else ``budget.check_budget``'s; ``retry_timeouts`` runs a timed-out check once
    more under ``RETRY_BUDGET_S`` or its first budget, whichever is longer, and the retry's result
    stands. Loading executes the file's top level, so it runs isolated too; ``check`` is the file
    already loaded (a test file run directly), and a file that fails to load is an
    ``unloadable`` result. ``ctx_factory`` checks the endpoint; ``run_config`` is recorded in the
    report's ``config``. A budget that is not a finite, positive number of seconds raises
    ``ValueError`` before anything runs.
    """
    path = Path(path)
    if timeout_s is not None:
        require_positive_seconds(timeout_s, "timeout_s")
    require_positive_seconds(cleanup_timeout_s, "cleanup_timeout_s")
    service = path.resolve().parent.name
    verify, tls = emulator_tls(endpoint, verify_ssl)
    with isolate.isolated(verify):
        try:
            check = check or load_check(path)
        except (Exception, SystemExit) as exc:  # graded, not swallowed
            result = _unloadable_result(path, service, exc)
        else:

            def attempt(budget: float | None) -> CheckResult:
                try:
                    return run_check(
                        ctx_factory,
                        check.name,
                        check.group,
                        check.run,
                        timeout_s=budget,
                        cleanup_timeout_s=cleanup_timeout_s,
                        service=service,
                    )
                except Exception as exc:  # a runner failure is never a finding
                    return _runner_failure(check.name, check.group, service, exc)

            result = attempt(timeout_s)
            if retry_timeouts and result.timed_out:
                result = attempt(max(RETRY_BUDGET_S, result.budget_s))
                result.retried_after_timeout = True
    result.check_id = manifest_check_id(path)
    logger.info(
        "[%s/%s] %s ... %s (%.0fms)",
        result.service,
        result.group,
        result.name,
        status_label(result),
        result.duration_ms,
    )
    report = {
        "schema": REPORT_SCHEMA,
        "endpoint": endpoint,
        "file": path.name,
        "check": check_entry(result),
        "emulator_tls": tls,
        "config": dict(run_config or {}),
    }
    return result, report
