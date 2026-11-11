"""cdk-watch-default-hotswap-ignores-non-hotswappable-property-edit."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-watch-default-hotswap-ignores-non-hotswappable-property-edit"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_APP = "cdk_watch_fn"
# Overrides cdk.json's "python3 app.py" with the interpreter running this check.
_APP_COMMAND = f"{sys.executable} app.py"

_INITIAL_DEPLOY_TIMEOUT_S = 420.0
_HOTSWAP_TIMEOUT_S = 150.0
_ABSENCE_FACTOR = 3.0
_ABSENCE_FLOOR_S = 30.0
_STOP_TIMEOUT_S = 30.0
_LOG_REAP_BUDGET_S = 180.0


@tags("axis:negative-delivery", "cap:c3", "concern:deploy", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Plain `cdk watch` (implied --hotswap, no fallback) hotswaps a code-only source edit, but a
    later edit to Timeout (non-hotswappable) never reaches the function or the stack at all —
    not hotswapped and not fallen back to, simply never deployed while watch keeps running.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-cdkwig-")
    marker1 = ctx.unique_name("m1-")
    marker2 = ctx.unique_name("m2-")
    marker3 = ctx.unique_name("m3-")

    work, app_path, log_path = _stage_app(ctx, stack, marker1, 10)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))

    # `cdk watch` with the default --hotswap (no fallback) cannot create a stack that does not
    # exist yet — hotswap is impossible against nothing, and with no fallback it is simply
    # skipped — so the stack is bootstrapped with an ordinary `cdk deploy` first.
    _cdk_deploy(ctx, work, stack, timeout_s=_INITIAL_DEPLOY_TIMEOUT_S)
    stack_desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert stack_desc["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {stack_desc['StackStatus']!r} right after its first deploy, "
        f"expected CREATE_COMPLETE"
    )
    stack_id = stack_desc["StackId"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack_desc.get("Outputs", [])}
    fn_name = outputs["FunctionName"]
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}",
                                           budget_s=_LOG_REAP_BUDGET_S))

    proc = _start_watch(ctx, work, log_path, [])
    ctx.on_cleanup(lambda: _stop_watch(proc))

    baseline_updated = stack_desc.get("LastUpdatedTime")
    config0 = lam.get_function(FunctionName=fn_name)["Configuration"]
    code0 = config0["CodeSha256"]
    assert config0["Timeout"] == 10, (
        f"freshly deployed Timeout was {config0['Timeout']!r}, expected 10"
    )

    # ---- positive control #1: a code-only edit still hotswaps under plain --hotswap ----
    start = time.monotonic()
    _edit_literal(app_path, "MARKER", marker2)
    _wait_code_change(lam, fn_name, code0, proc, log_path, timeout_s=_HOTSWAP_TIMEOUT_S)
    latency_s = time.monotonic() - start
    config1 = lam.get_function(FunctionName=fn_name)["Configuration"]
    code1 = config1["CodeSha256"]
    assert config1["Timeout"] == 10, (
        f"Timeout became {config1['Timeout']!r} from a deploy that only changed the code"
    )
    payload1 = _invoke(lam, fn_name)
    assert payload1 == {"marker": marker2}, (
        f"after the hotswap, invoke returned {payload1!r}, expected {{'marker': {marker2!r}}}"
    )

    # ---- the negative: a Timeout edit is not hotswappable and, with no fallback, is ignored ----
    _edit_literal(app_path, "TIMEOUT_SECONDS", "20")
    seen_timeouts = _hold_for(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["Timeout"],
        latency_s, proc, log_path, factor=_ABSENCE_FACTOR, floor_s=_ABSENCE_FLOOR_S,
    )
    assert set(seen_timeouts) == {10}, (
        f"Timeout read as {sorted(set(seen_timeouts))!r} while holding for the ignored edit, "
        f"expected only the original 10 — the edit must never reach the function"
    )
    stack_after_ignore = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert stack_after_ignore.get("LastUpdatedTime") == baseline_updated, (
        f"stack {stack!r}'s LastUpdatedTime moved from {baseline_updated!r} to "
        f"{stack_after_ignore.get('LastUpdatedTime')!r} — an ignored property edit must not touch "
        f"the stack at all"
    )

    # ---- positive control #2: the watcher is still alive and still hotswaps afterward ----
    _edit_literal(app_path, "MARKER", marker3)
    _wait_code_change(lam, fn_name, code1, proc, log_path, timeout_s=_HOTSWAP_TIMEOUT_S)
    config2 = lam.get_function(FunctionName=fn_name)["Configuration"]
    assert config2["Timeout"] == 10, (
        f"Timeout is {config2['Timeout']!r} after the second hotswap — the earlier ignored edit "
        f"must stay ignored, not apply itself on a later deploy"
    )
    payload2 = _invoke(lam, fn_name)
    assert payload2 == {"marker": marker3}, (
        f"after the second hotswap, invoke returned {payload2!r}, expected {{'marker': "
        f"{marker3!r}}} — the watcher must still be alive and processing edits"
    )

    _stop_watch(proc)
    assert proc.poll() is not None, "cdk watch did not stop within its bounded shutdown window"


# ===== helpers =====

def _invoke(lam, fn_name: str) -> dict:
    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    assert "FunctionError" not in resp, (
        f"invoke of {fn_name!r} errored: {resp['Payload'].read()[:400]!r}"
    )
    return json.loads(resp["Payload"].read())


def _log_tail(log_path: Path) -> str:
    try:
        return log_path.read_text(errors="replace")[-1500:]
    except OSError:
        return "<no watch log available>"


def _assert_alive(proc, log_path: Path, context: str) -> None:
    rc = proc.poll()
    assert rc is None, (
        f"`cdk watch` exited ({rc}) while waiting for {context}; output tail: "
        f"{_log_tail(log_path)!r}"
    )


def _wait_code_change(lam, fn_name: str, baseline_sha: str, proc, log_path: Path, *,
                      timeout_s: float, poll_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        _assert_alive(proc, log_path, "the hotswapped CodeSha256 to change")
        config = lam.get_function(FunctionName=fn_name)["Configuration"]
        if config["CodeSha256"] != baseline_sha and config.get("LastUpdateStatus") == "Successful":
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"CodeSha256 for {fn_name!r} stayed {baseline_sha!r} for {timeout_s}s after a "
                f"code edit; output tail: {_log_tail(log_path)!r}"
            )
        time.sleep(poll_s)


def _hold_for(observe, latency_s: float, proc, log_path: Path, *, factor: float,
             floor_s: float, poll_s: float = 2.0) -> list:
    """Every value ``observe()`` returns over ``max(floor_s, factor * latency_s)``, so a late
    apply of the ignored edit is caught and quoted rather than missed by a single read."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        _assert_alive(proc, log_path, "the held-for window on the ignored edit")
        seen.append(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _edit_literal(app_path: Path, name: str, value: str) -> None:
    """Rewrite the ``NAME = ...`` literal assignment in *app_path* on disk, in place.

    Editing the file (not passing a new --context) is what `cdk watch`'s own file watcher reacts
    to: a new deploy it triggers itself, not one the check drives.
    """
    text = app_path.read_text()
    literal = f'"{value}"' if isinstance(value, str) and not value.isdigit() else value
    pattern = re.compile(rf"^{name} = .*$", re.MULTILINE)
    new_text, count = pattern.subn(f"{name} = {literal}", text, count=1)
    assert count == 1, f"expected exactly one {name!r} assignment in {app_path}, replaced {count}"
    app_path.write_text(new_text)


def _stage_app(ctx, stack: str, marker: str, timeout: int) -> tuple[Path, Path, Path]:
    """Copy `deployments/cdk_watch_fn` into a temp dir with its placeholders filled in.

    Returns (work dir, app.py path, watch log path).
    """
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-watch-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / _APP
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    app_path = staged / "app.py"
    text = app_path.read_text()
    text = (text.replace("__STACK_NAME__", stack)
               .replace("__ACCOUNT__", ctx.account)
               .replace("__REGION__", ctx.region)
               .replace("__MARKER__", marker)
               .replace("__TIMEOUT__", str(timeout)))
    app_path.write_text(text)
    return staged, app_path, work / "watch.log"


def _cdk_deploy(ctx, work: Path, stack: str, *, timeout_s: float) -> None:
    """Run an ordinary, blocking `cdk deploy` and assert it exits 0."""
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    cmd = ["cdk", "deploy", stack, "--require-approval", "never", "--app", _APP_COMMAND, "--ci",
           "--no-color", "--no-notices", "--no-version-reporting"]
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=timeout_s)
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"`cdk deploy {stack}` exited {result.returncode}, expected 0; output tail: "
        f"{output[-1200:]!r}"
    )


def _start_watch(ctx, work: Path, log_path: Path, extra_args: list[str]) -> subprocess.Popen:
    """Start `cdk watch` in *work*, logging combined output to *log_path*."""
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    cmd = ["cdk", "watch", *extra_args, "--app", _APP_COMMAND, "--ci", "--no-color",
           "--no-notices", "--no-version-reporting"]
    log_fh = log_path.open("wb")
    proc = subprocess.Popen(cmd, cwd=work, env=env, stdout=log_fh, stderr=subprocess.STDOUT,
                            start_new_session=True)
    return proc


def _stop_watch(proc: subprocess.Popen) -> None:
    """Stop the `cdk watch` process group, escalating from SIGINT to SIGKILL; idempotent."""
    if proc.poll() is not None:
        return
    for sig, wait_s in ((signal.SIGINT, _STOP_TIMEOUT_S), (signal.SIGTERM, 15.0),
                       (signal.SIGKILL, 15.0)):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait_s)
            return
        except subprocess.TimeoutExpired:
            continue


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _delete_stack_and_wait(cfn, stack_id: str, *, timeout_s: float = 300.0) -> None:
    """Delete by name or id; a stack gone before deletion starts, or whose DELETE_COMPLETE a
    by-name describe no longer shows, is a no-op rather than a failure."""
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id!r} teardown ended {status!r}")
        time.sleep(5.0)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} "
                    f"clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
