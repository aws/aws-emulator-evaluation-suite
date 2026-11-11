"""Run a fidelity test file against an AWS emulator."""

from importlib.metadata import PackageNotFoundError, version

from fidelity_tests_runner.context import Context
from fidelity_tests_runner.harness import (
    EXIT_CLEANUP,
    EXIT_ERROR,
    EXIT_FAILED,
    EXIT_PASS,
    VERDICT_ERROR,
    VERDICT_FAILED,
    VERDICT_PASSED,
    CheckResult,
    RequiredModuleMissing,
    RequiredToolMissing,
    require_modules,
    require_tools,
    tags,
)
from fidelity_tests_runner.run import load_check, run_check, run_file

try:
    __version__ = version("fidelity-tests-runner")
except PackageNotFoundError:  # a source tree on PYTHONPATH, not installed
    __version__ = "0+unknown"


def main(run, *, argv: list[str] | None = None) -> None:
    """Every fidelity test's footer: ``from fidelity_tests_runner import main; main(run)``.

    Never returns.
    """
    from fidelity_tests_runner.cli import check_main  # noqa: PLC0415 - the CLI imports this package

    check_main(run, argv=argv)


__all__ = [
    "EXIT_CLEANUP",
    "EXIT_ERROR",
    "EXIT_FAILED",
    "EXIT_PASS",
    "VERDICT_ERROR",
    "VERDICT_FAILED",
    "VERDICT_PASSED",
    "CheckResult",
    "Context",
    "RequiredModuleMissing",
    "RequiredToolMissing",
    "load_check",
    "main",
    "require_modules",
    "require_tools",
    "run_check",
    "run_file",
    "tags",
]
