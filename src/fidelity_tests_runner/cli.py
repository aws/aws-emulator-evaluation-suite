"""The command line: ``fidelity-tests-runner run``, ``summarize`` and ``requirements``.

A fidelity test file ends with ``if __name__ == "__main__": from fidelity_tests_runner import main;
main(run)``, so ``python check_x.py --endpoint <url>`` runs it through the same path as
``fidelity-tests-runner run check_x.py``, with the same options, output and exit code:
``EXIT_PASS`` / ``EXIT_FAILED`` / ``EXIT_ERROR``, ``EXIT_CLEANUP`` for a failed teardown under
``--strict-cleanup``, and 2 for an input error.
"""

import argparse
import json
import logging
import os
import re
import stat
import sys
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any, TextIO

import botocore

from fidelity_tests_runner import __version__, credentials, isolate, verdicts
from fidelity_tests_runner.budget import (
    EMULATOR_BUDGET_S,
    EMULATOR_MAX_BUDGET_S,
    REAL_TIME_TAG,
    RETRY_BUDGET_S,
    SLOW_TOOLS,
    positive_seconds,
)
from fidelity_tests_runner.context import FIXED_CREDS, Context
from fidelity_tests_runner.harness import (
    DEFAULT_CLEANUP_TIMEOUT_S,
    DEFAULT_REGION,
    EXIT_CLEANUP,
    EXIT_ERROR,
    EXIT_FAILED,
    EXIT_PASS,
    VERDICT_ERROR,
    VERDICT_FAILED,
    VERDICT_PASSED,
    CheckResult,
    exit_process,
)
from fidelity_tests_runner.requirements import requirements_of
from fidelity_tests_runner.run import (
    REPORT_SCHEMA,
    LoadedCheck,
    loaded_from,
    run_file,
    status_label,
)
from fidelity_tests_runner.target import is_loopback_endpoint, require_loopback

_EXIT_FOR_VERDICT = {
    VERDICT_PASSED: EXIT_PASS,
    VERDICT_FAILED: EXIT_FAILED,
    VERDICT_ERROR: EXIT_ERROR,
}


class InputError(ValueError):
    """The run's own input is wrong; nothing was sent to the emulator."""


def add_target_arguments(ap: argparse.ArgumentParser) -> None:
    """The options of a test run: the emulator, how to authenticate to it, budgets, the report."""
    ap.add_argument("--endpoint", required=True, help="the emulator's base URL")
    ap.add_argument("--region", default=DEFAULT_REGION)
    ap.add_argument(
        "--timeout",
        type=positive_seconds,
        help=f"test budget (s); by default {EMULATOR_MAX_BUDGET_S:.0f} for a {REAL_TIME_TAG} "
        f"test or one that requires {', '.join(sorted(SLOW_TOOLS))}, "
        f"else {EMULATOR_BUDGET_S:.0f}",
    )
    ap.add_argument(
        "--retry-timeout",
        "--retry-timeouts",
        dest="retry_timeout",
        action="store_true",
        help=f"run a timed-out test once more under max({RETRY_BUDGET_S:.0f}s, its budget); "
        "the retry's verdict stands",
    )
    ap.add_argument(
        "--strict-cleanup",
        action="store_true",
        help=f"exit {EXIT_CLEANUP} when a teardown raised or did not finish (the verdict stands)",
    )
    ap.add_argument(
        "--cleanup-timeout",
        type=positive_seconds,
        default=DEFAULT_CLEANUP_TIMEOUT_S,
        help="teardown budget (s)",
    )
    ap.add_argument(
        "--auth",
        choices=("on", "off"),
        default="on",
        help="on (default): sign with the keys the emulator minted, and refuse to run without "
        "them; off: sign with the fixed keys test/test",
    )
    ap.add_argument(
        "--credentials-file",
        type=Path,
        help="the emulator's key file (aws_access_key_id=... / aws_secret_access_key=...); "
        "default: <emulator home>/<dir>/<port>/emulator_credentials",
    )
    ap.add_argument(
        "--emulator-home",
        type=Path,
        help="the HOME the emulator was started with, searched for its key file and CA "
        "(default: this process's HOME)",
    )
    ap.add_argument(
        "--ca-bundle",
        help="CA bundle to verify an https emulator against (default: the ca.pem it publishes "
        "beside its keys, for a loopback endpoint)",
    )
    ap.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="do not verify TLS; loopback endpoints only",
    )
    ap.add_argument(
        "--execute-api-url",
        help="the emulator's API Gateway invoke-URL template, for ctx.api_url "
        "(default: FIDELITY_TESTS_EXECUTE_API_URL_TEMPLATE; with none, a test that needs an "
        "invoke URL fails)",
    )
    ap.add_argument(
        "--s3-website-url",
        metavar="TEMPLATE",
        help="the emulator's S3 website endpoint template, an http(s) URL naming {bucket} and only "
        "{region}, {host} and {port} (the endpoint's), for ctx.s3_website_urls (default: "
        "FIDELITY_TESTS_S3_WEBSITE_URL)",
    )
    ap.add_argument(
        "--own-host",
        action="append",
        metavar="HOST|*.SUFFIX",
        help="a documented own host of the emulator beyond loopback and the endpoint host "
        "(repeatable; default: FIDELITY_TESTS_OWN_HOSTS)",
    )
    ap.add_argument(
        "--report",
        help="write the JSON report to this file, or - for stdout (the console line then goes to "
        "stderr)",
    )


def resolve_creds(
    endpoint: str, auth: str, credentials_file: Path | None, emulator_home: Path | None
) -> dict[str, str]:
    """The key pair every client signs with, or ``InputError`` when ``--auth on`` finds none."""
    if emulator_home is not None:
        if not emulator_home.is_dir():
            raise InputError(f"--emulator-home {emulator_home} is not a directory")
        credentials.key_home = emulator_home
    if auth == "off":
        if credentials_file is not None:
            raise InputError("--credentials-file needs --auth on")
        return dict(FIXED_CREDS)
    try:
        if credentials_file is not None:
            minted = credentials.read_key_file(credentials_file)
        else:
            minted = credentials.minted_credentials(endpoint)
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    if minted is None and not is_loopback_endpoint(endpoint):
        raise InputError(
            f"--auth on: key files are looked up for a loopback endpoint only, not {endpoint}; "
            "pass --credentials-file, or --auth off for an emulator started without auth"
        )
    if minted is None:
        home = credentials.key_home or Path.home()
        raise InputError(
            f"--auth on: no key file for {endpoint} under {home} (an --auth on emulator writes "
            f"<dir>/<port>/{credentials.KEY_FILE} there); pass --credentials-file or "
            "--emulator-home, or --auth off for an emulator started without auth"
        )
    return {"aws_access_key_id": minted.access_key, "aws_secret_access_key": minted.secret_key}


@cache
def _region_patterns() -> tuple[re.Pattern, ...]:
    """Every partition's region name pattern, from botocore's ``partitions.json``."""
    data = json.loads((Path(botocore.__file__).parent / "data" / "partitions.json").read_text())
    return tuple(re.compile(p["regionRegex"]) for p in data["partitions"])


def require_region(region: str) -> None:
    """Raise ``InputError`` unless ``region`` is shaped like a region of some AWS partition."""
    if not any(p.fullmatch(region) for p in _region_patterns()):
        raise InputError(f"--region {region!r} is not an AWS region name")


def context_factory(args: argparse.Namespace) -> tuple[Callable[[], Context], bool | str]:
    """A factory of Contexts for the parsed target options, and the ``verify`` it uses.

    Every input is checked here, before anything runs, so an input error is never a verdict; an
    AWS endpoint is refused before any key is read.
    """
    try:
        isolate.refuse_optimized()
    except isolate.OptimizedPython as exc:
        raise InputError(str(exc)) from exc
    try:
        require_loopback(args.endpoint)
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    require_region(args.region)
    if args.ca_bundle and args.no_verify_ssl:
        raise InputError("--ca-bundle and --no-verify-ssl contradict each other")
    if args.ca_bundle and not Path(args.ca_bundle).is_file():
        raise InputError(f"--ca-bundle {args.ca_bundle} is not a file")
    verify: bool | str = args.ca_bundle or not args.no_verify_ssl
    creds = resolve_creds(args.endpoint, args.auth, args.credentials_file, args.emulator_home)

    def factory() -> Context:
        return Context(
            args.endpoint,
            args.region,
            verify_ssl=verify,
            creds=creds,
            execute_api_url=args.execute_api_url,
            s3_website_url=getattr(args, "s3_website_url", None),
            own_hosts=getattr(args, "own_host", None),
        )

    try:
        factory()
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    return factory, verify


def run_config(args: argparse.Namespace) -> dict[str, Any]:
    """The run options a report records: every one that weakens a default, and the budget's."""
    return {
        "auth": args.auth,
        "credentials_file": args.credentials_file is not None,
        "ca_bundle": bool(args.ca_bundle),
        "no_verify_ssl": bool(args.no_verify_ssl),
        "timeout_s": args.timeout,
        "retry_timeout": bool(args.retry_timeout),
    }


#: Characters a terminal may act on: C0 and C1 controls but newline and tab, and DEL.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _printable(text: str) -> str:
    """``text`` with every terminal control character shown as its escape, never sent raw.

    A detail carries what the emulator answered, which must not move the cursor, recolour, retitle
    or rewrite a line of the console.
    """
    return _CONTROL.sub(lambda m: m.group(0).encode("unicode_escape").decode("ascii"), text)


def _print_result(result: CheckResult, out: TextIO) -> None:
    status = status_label(result)
    kind = verdicts.classify(result)
    if kind not in (verdicts.KIND_PASSED, verdicts.KIND_FAILED, verdicts.KIND_NOT_UP):
        status = f"{status} [{kind}]"
    if result.retried_after_timeout:
        status = f"{status} (retry after a timeout)"
    line = f"[{result.group}] {result.name} ... {status} ({result.duration_ms:.0f}ms)"
    print(_printable(line), file=out)
    if result.detail and not result.passed:
        print(_printable(result.detail), file=out)
    if result.cleanup_detail:
        print(_printable(f"cleanup: {result.cleanup_detail}"), file=out)


def open_report(path: Path) -> TextIO:
    """``path`` opened for the report: readable by this user only, never through a link.

    An existing file must be a regular file this user owns; it is emptied. Anything else raises
    ``InputError``, before the check runs.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise InputError(f"--report {path}: {exc.strerror or exc}") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        os.close(fd)
        raise InputError(f"--report {path} is not a regular file this user owns")
    os.fchmod(fd, 0o600)
    os.ftruncate(fd, 0)
    return open(fd, "w", encoding="utf-8")


def _exit_code(result: CheckResult, strict_cleanup: bool) -> int:
    if strict_cleanup and result.cleanup_failed:
        return EXIT_CLEANUP
    return _EXIT_FOR_VERDICT[result.verdict]


def run_test(
    args: argparse.Namespace,
    ap: argparse.ArgumentParser,
    path: Path,
    check: LoadedCheck | None = None,
) -> int:
    """Run one test file for parsed ``args``: print its result, write its report, exit code.

    ``check`` is the file already loaded (a test file run directly). Exits the process at once,
    without waiting for its threads, when the test timed out or was retried after a timeout.
    """
    try:
        factory, verify = context_factory(args)
        out = open_report(Path(args.report)) if args.report and args.report != "-" else None
    except InputError as exc:
        ap.error(str(exc))
    result, report = run_file(
        path,
        factory,
        endpoint=args.endpoint,
        verify_ssl=verify,
        timeout_s=args.timeout,
        cleanup_timeout_s=args.cleanup_timeout,
        retry_timeouts=args.retry_timeout,
        run_config=run_config(args),
        check=check,
    )
    _print_result(result, sys.stderr if args.report == "-" else sys.stdout)
    if args.report:
        text = json.dumps(report, indent=2, sort_keys=True)
        if out is None:
            print(text)
        else:
            with out:
                out.write(text + "\n")
    code = _exit_code(result, args.strict_cleanup)
    if result.timed_out or result.retried_after_timeout:
        exit_process(code, abandon=True)  # its threads would hold a normal exit past the budget
    return code


def check_main(run: Callable[[Any], None], *, argv: list[str] | None = None) -> None:
    """A test file run directly: as ``fidelity-tests-runner run <file>``. Never returns.

    The module's top-level code ran on import, before isolation begins.
    """
    path, check = loaded_from(run)
    ap = argparse.ArgumentParser(description=f"Run fidelity test {check.name!r} on an emulator")
    add_target_arguments(ap)
    exit_process(run_test(ap.parse_args(argv), ap, path, check))


def _cmd_run(args: argparse.Namespace, ap: argparse.ArgumentParser) -> int:
    path = Path(args.check)
    if not path.is_file():
        ap.error(f"{path} is not a file")
    return run_test(args, ap, path)


def _report_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        files += sorted(path.rglob("*.json")) if path.is_dir() else [path]
    return files


def summarize(paths: list[str]) -> tuple[dict[str, Any], list[str]]:
    """``verdicts.score`` over the reports ``fidelity-tests-runner run`` wrote, and the problems.

    Also ``by_service``: the score of each service's checks. A file that is not such a report is
    named in the problems and left out.
    """
    rows: list[tuple[str, str, str, bool]] = []
    problems: list[str] = []
    for path in _report_files(paths):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            problems.append(f"{path}: {exc}")
            continue
        if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
            problems.append(f"{path}: not a {REPORT_SCHEMA} report")
            continue
        check = report.get("check")
        if not isinstance(check, dict):
            check = {}
        test, kind = check.get("check_id"), check.get("kind")
        if not isinstance(test, str) or kind not in verdicts.KINDS:
            problems.append(f"{path}: not a {REPORT_SCHEMA} report: no check_id or known kind")
            continue
        svc = str(check.get("service", ""))
        rows.append((test, svc, kind, bool(check.get("cleanup_failed"))))
    services: dict[str, list[tuple[str, str, bool]]] = {}
    for test, svc, kind, cleanup_failed in rows:
        services.setdefault(svc, []).append((test, kind, cleanup_failed))
    summary = verdicts.tally((t, k, c) for t, _, k, c in rows)
    summary["by_service"] = {svc: verdicts.tally(rs) for svc, rs in sorted(services.items())}
    return summary, problems


def _cmd_summarize(args: argparse.Namespace, ap: argparse.ArgumentParser) -> int:
    summary, problems = summarize(args.reports)
    for problem in problems:
        print(f"skipped {problem}", file=sys.stderr)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["n_total"] else 1
    print(
        f"n={summary['n']} passed={summary['passed']} pass_rate={summary['pass_rate']:.4f} "
        f"coverage={summary['coverage']:.4f} ({summary['n']}/{summary['n_total']} scored) "
        f"cleanup_failed={summary['n_cleanup_failed']}"
    )
    failed = " ".join(f"{k}={v}" for k, v in summary["failed_by_kind"].items() if v)
    excluded = " ".join(f"{k}={v}" for k, v in summary["excluded_by_kind"].items() if v)
    print(f"failed: {failed or '-'}")
    print(f"excluded: {excluded or '-'}")
    if args.by_service:
        for svc, score in summary["by_service"].items():
            print(f"  {svc}: {score['passed']}/{score['n']} ({score['pass_rate']:.4f})")
    return 0 if summary["n_total"] else 1


def _cmd_requirements(args: argparse.Namespace, ap: argparse.ArgumentParser) -> int:
    reports = []
    for raw in args.checks:
        path = Path(raw)
        if not path.is_file():
            ap.error(f"{path} is not a file")
        reports.append(requirements_of(path))
    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        for r in reports:
            print(r["file"])
            for key in ("tools", "python_packages", "missing_tools", "missing_python_packages"):
                print(f"  {key}: {', '.join(r[key]) or '-'}")
            for note in r["notes"]:
                print(f"  note: {note}")
    return 1 if any(r["missing_tools"] or r["missing_python_packages"] for r in reports) else 0


def main(argv: list[str] | None = None) -> int:
    """``fidelity-tests-runner`` console entrypoint."""
    ap = argparse.ArgumentParser(
        prog="fidelity-tests-runner",
        description="Run AWS behavioral fidelity tests against an emulator.",
    )
    ap.add_argument("--version", action="version", version=f"fidelity-tests-runner {__version__}")
    ap.add_argument("-v", "--verbose", action="store_true", help="log at INFO")
    sub = ap.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run one fidelity test file against an emulator")
    run_p.add_argument(
        "check", metavar="TEST", help="path to a fidelity test file, check_<name>.py"
    )
    add_target_arguments(run_p)

    req_p = sub.add_parser(
        "requirements",
        help="list the tools and Python packages fidelity tests need, and which are absent",
    )
    req_p.add_argument(
        "checks", nargs="+", metavar="TEST", help="fidelity test files (check_<name>.py)"
    )
    req_p.add_argument("--json", action="store_true")

    sum_p = sub.add_parser(
        "summarize",
        aliases=["score"],
        help="score the reports `run` wrote: n, passed, failure kinds, exclusions",
    )
    sum_p.add_argument(
        "reports", nargs="+", help="report files, or directories searched for *.json"
    )
    sum_p.add_argument("--by-service", action="store_true", help="one line per service")
    sum_p.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    if args.command == "run":
        return _cmd_run(args, run_p)
    if args.command in ("summarize", "score"):
        return _cmd_summarize(args, sum_p)
    return _cmd_requirements(args, req_p)
