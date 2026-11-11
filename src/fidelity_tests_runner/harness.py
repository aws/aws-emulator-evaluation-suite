"""What every check and the runner share: verdicts, exit codes, tags, tools, results."""

import atexit
import importlib.util
import logging
import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import NoReturn

#: The region a run defaults to.
DEFAULT_REGION = "us-west-2"

#: A failed assertion observed the target and disagreed (a fidelity finding); anything else a
#: check raised never made a clean observation (a runner or target fault).
VERDICT_PASSED = "passed"
VERDICT_FAILED = "failed"
VERDICT_ERROR = "error"

#: Process exit codes for one check, clear of Python's and argparse's 1 and 2.
EXIT_PASS = 0
EXIT_FAILED = 11
EXIT_ERROR = 12
#: ``--strict-cleanup``: the check's teardown raised or did not finish; the verdict is reported.
EXIT_CLEANUP = 13

#: The teardown budget. Exceeding it is reported and never graded.
DEFAULT_CLEANUP_TIMEOUT_S = 60.0

#: Binaries a check may require; a runner without one reports the check ``tool_missing``.
KNOWN_TOOLS = (
    "aws",
    "terraform",
    "tofu",
    "cdk",
    "docker",
    "kubectl",
    "git",
    "openssl",
    "npm",
    "node",
    "sftp",
    "ssh",
    "ssh-keygen",
    "ffmpeg",
    "ffprobe",
    "gst-launch-1.0",
)


def exit_process(code: int, *, abandon: bool = False) -> NoReturn:
    """Exit with ``code``; with ``abandon``, without waiting for a timed-out check's threads.

    A check's thread cannot be stopped, and a normal exit joins every thread it started (a
    ``ThreadPoolExecutor``'s workers, daemon or not). ``atexit`` handlers run either way.
    """
    if abandon:
        atexit._run_exitfuncs()
        logging.shutdown()
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    sys.exit(code)


def tags(*values: str):
    """Classify a check. No runtime effect beyond ``fn.__fidelity_test_tags__``."""

    def deco(fn):
        fn.__fidelity_test_tags__ = (*getattr(fn, "__fidelity_test_tags__", ()), *values)
        return fn

    return deco


@dataclass
class CheckResult:
    """The outcome of one check."""

    name: str
    group: str
    passed: bool
    detail: str | None
    duration_ms: float
    #: One of the ``VERDICT_*`` constants.
    verdict: str
    #: The failure reads as "nothing was listening": a bootstrap failure, not a fidelity finding.
    not_up: bool = False
    #: The unit a failure is attributed to; the check's own name unless set.
    operation: str = ""
    service: str = ""
    #: Teardown time, kept out of ``duration_ms`` so the measurement is the check's.
    cleanup_ms: float = 0.0
    #: Why teardown did not finish (resources may remain), or ``""``.
    cleanup_detail: str = ""
    #: Where a failed check failed (``fidelity_tests_runner.site``), or ``None``.
    site: dict | None = None
    #: Tools the runner lacked (``RequiredToolMissing``): a runner fault, not a fidelity finding.
    tool_missing: tuple[str, ...] = ()
    #: ``run(ctx)`` exceeded its deadline; its threads may still be running, so a process exits
    #: without waiting for them.
    timed_out: bool = False
    #: Why the runner, not the target, failed the test (``verdicts.FAULT_*``), or ``""``.
    runner_fault: str = ""
    #: The check file did not load.
    unloadable: bool = False
    #: A teardown raised or did not finish; the verdict is unchanged.
    cleanup_failed: bool = False
    #: This result is the retry of a check that timed out.
    retried_after_timeout: bool = False
    #: The budget the check ran under, in seconds.
    budget_s: float = 0.0
    #: ``{field, reason, value_class, host}`` per published value the test could not use.
    published_url_violations: tuple[dict[str, str], ...] = ()
    #: The test's ID in the suite's ``manifest.jsonl``, the ID published scores use; ``""`` for a
    #: file outside a suite, whose ID is ``<service>.<name>``.
    check_id: str = ""


def scrub_paths(text: str) -> str:
    """Reduce absolute paths in traceback frames to file names, so details stay portable."""
    return re.sub(r'File "([^"]*/)?([^"/]+)"', r'File "\2"', text)


class RequiredToolMissing(RuntimeError):
    """The runner lacks a tool a check needs: an environment defect, flagged ``tool_missing``."""

    def __init__(self, tools: list[str], what: str = "tool"):
        super().__init__(
            f"runner is missing required {what}(s): {', '.join(tools)}; install them in the image"
        )
        self.tools = tools


class RequiredModuleMissing(RequiredToolMissing):
    """The runner lacks a Python module a check imports: flagged ``tool_missing`` like a tool."""

    def __init__(self, modules: list[str]):
        super().__init__(modules, "module")


def _module_missing(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is None
    except (ModuleNotFoundError, ValueError):
        return True


def require_modules(*modules: str) -> None:
    """Assert every named Python module is importable, before the check imports it."""
    missing = [m for m in modules if _module_missing(m)]
    if missing:
        raise RequiredModuleMissing(missing)


def require_tools(*tools: str) -> None:
    """Assert every named binary is on ``PATH``."""
    unknown = [t for t in tools if t not in KNOWN_TOOLS]
    if unknown:
        raise ValueError(f"unknown tool(s) {unknown}; add to KNOWN_TOOLS if genuinely needed")
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise RequiredToolMissing(missing)
