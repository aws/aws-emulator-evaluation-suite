"""cdk-watch-lambda-code-edit-hotswaps-then-timeout-edit-falls-back."""
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

CHECK = "cdk-watch-lambda-code-edit-hotswaps-then-timeout-edit-falls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_APP = "cdk_watch_fn"
# Overrides cdk.json's "python3 app.py" with the interpreter running this check.
_APP_COMMAND = f"{sys.executable} app.py"
_STACK_RESOURCE_TYPE = "AWS::CloudFormation::Stack"
_FUNCTION_RESOURCE_TYPE = "AWS::Lambda::Function"

_INITIAL_DEPLOY_TIMEOUT_S = 420.0
_HOTSWAP_TIMEOUT_S = 150.0
_FALLBACK_DEPLOY_TIMEOUT_S = 420.0
_STOP_TIMEOUT_S = 30.0
_LOG_REAP_BUDGET_S = 180.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`cdk watch --hotswap-fallback`: a source edit to the function's inline code lands through
    a hotswap with no stack event, and a later edit to Timeout (non-hotswappable) is reconciled
    through a full CloudFormation deployment instead.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-cdkwfb-")
    marker1 = ctx.unique_name("m1-")
    marker2 = ctx.unique_name("m2-")

    work, app_path, log_path = _stage_app(ctx, stack, marker1, 10)
    # Cleanups run LIFO: the watch process stops before the stack it could redeploy is deleted.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    proc = _start_watch(ctx, work, log_path, ["--hotswap-fallback"])
    ctx.on_cleanup(lambda: _stop_watch(proc))

    stack_id = _wait_stack_status(cfn, stack, "CREATE_COMPLETE", proc, log_path,
                                  timeout_s=_INITIAL_DEPLOY_TIMEOUT_S)
    stack_desc = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack_desc.get("Outputs", [])}
    fn_name = outputs["FunctionName"]
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}",
                                           budget_s=_LOG_REAP_BUDGET_S))

    baseline_updated = stack_desc.get("LastUpdatedTime")
    baseline_events = _stack_level_events(cfn, stack_id)
    config0 = lam.get_function(FunctionName=fn_name)["Configuration"]
    code0 = config0["CodeSha256"]
    assert config0["Timeout"] == 10, (
        f"freshly deployed Timeout was {config0['Timeout']!r}, expected 10"
    )
    payload0 = _invoke(lam, fn_name)
    assert payload0 == {"marker": marker1}, (
        f"the freshly deployed function returned {payload0!r}, expected {{'marker': {marker1!r}}}"
    )

    # ---- a code-only edit lands through a hotswap: no stack event, no LastUpdatedTime move ----
    hotswap_start = time.monotonic()
    _edit_literal(app_path, "MARKER", marker2)
    _wait_code_change(lam, fn_name, code0, proc, log_path, timeout_s=_HOTSWAP_TIMEOUT_S)
    hotswap_latency_s = time.monotonic() - hotswap_start
    config1 = lam.get_function(FunctionName=fn_name)["Configuration"]
    assert config1["Timeout"] == 10, (
        f"Timeout became {config1['Timeout']!r} from a deploy that only changed the code"
    )
    payload1 = _invoke(lam, fn_name)
    assert payload1 == {"marker": marker2}, (
        f"after the hotswap, invoke returned {payload1!r}, expected {{'marker': {marker2!r}}}"
    )

    held = _hold_for(lambda: cfn.describe_stacks(StackName=stack_id)["Stacks"][0],
                     hotswap_latency_s, proc, log_path, factor=3.0, floor_s=15.0)
    statuses = {s["StackStatus"] for s in held}
    assert statuses == {"CREATE_COMPLETE"}, (
        f"stack {stack!r} reported status(es) {sorted(statuses)!r} after a hotswapped code "
        f"edit, expected only CREATE_COMPLETE"
    )
    updated_times = {s.get("LastUpdatedTime") for s in held}
    assert updated_times == {baseline_updated}, (
        f"stack {stack!r}'s LastUpdatedTime moved to "
        f"{sorted(updated_times - {baseline_updated})!r} "
        f"(was {baseline_updated!r}) after a hotswapped code edit"
    )
    events_after_hotswap = _stack_level_events(cfn, stack_id)
    assert events_after_hotswap == baseline_events, (
        f"stack-level events changed from {baseline_events!r} to {events_after_hotswap!r} after a "
        f"hotswapped code edit — a hotswap must not produce any CloudFormation stack event"
    )
    fn_events_after_hotswap = _stack_level_events(cfn, stack_id, _FUNCTION_RESOURCE_TYPE)

    # ---- a Timeout edit is not hotswappable: it falls back to a full deployment ----
    _edit_literal(app_path, "TIMEOUT_SECONDS", "20")
    _wait_stack_updated(cfn, stack_id, baseline_updated, proc, log_path,
                        timeout_s=_FALLBACK_DEPLOY_TIMEOUT_S)
    config2 = lam.get_function(FunctionName=fn_name)["Configuration"]
    assert config2["Timeout"] == 20, (
        f"the function's Timeout is {config2['Timeout']!r} after the fallback deploy, expected 20"
    )
    payload2 = _invoke(lam, fn_name)
    assert payload2 == {"marker": marker2}, (
        f"after the fallback deploy, invoke returned {payload2!r}, expected the unchanged "
        f"{{'marker': {marker2!r}}} — the fallback must not revert the earlier hotswapped code"
    )
    after_fallback = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert after_fallback["StackStatus"] == "UPDATE_COMPLETE", (
        f"stack {stack!r} is {after_fallback['StackStatus']!r} after the fallback deploy, "
        f"expected UPDATE_COMPLETE"
    )
    events_after_fallback = _stack_level_events(cfn, stack_id)
    new_events = [e for e in events_after_fallback if e not in events_after_hotswap]
    new_statuses = {status for _, status in new_events}
    assert "UPDATE_COMPLETE" in new_statuses, (
        f"no new UPDATE_COMPLETE stack-level event appeared after the fallback deploy; new "
        f"stack-level events were {new_events!r}"
    )
    fn_events_after_fallback = _stack_level_events(cfn, stack_id, _FUNCTION_RESOURCE_TYPE)
    new_fn_statuses = {status for e_id, status in fn_events_after_fallback
                       if (e_id, status) not in fn_events_after_hotswap}
    assert new_fn_statuses, (
        f"no new event on the {_FUNCTION_RESOURCE_TYPE} resource appeared after the fallback "
        f"deploy that changed its Timeout"
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


def _stack_level_events(cfn, stack_id: str,
                        resource_type: str = _STACK_RESOURCE_TYPE) -> list[tuple[str, str]]:
    """``(EventId, ResourceStatus)`` for every event CloudFormation recorded against resources of
    *resource_type* (by default the stack resource itself)."""
    events: list[tuple[str, str]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for e in page["StackEvents"]:
            if e["ResourceType"] == resource_type:
                events.append((e["EventId"], e["ResourceStatus"]))
    return events


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


def _wait_stack_status(cfn, stack: str, want: str, proc, log_path: Path, *,
                       timeout_s: float, poll_s: float = 5.0) -> str:
    """Poll until the stack reaches *want*; returns its StackId."""
    deadline = time.monotonic() + timeout_s
    while True:
        _assert_alive(proc, log_path, f"the stack to reach {want!r}")
        try:
            stacks = cfn.describe_stacks(StackName=stack)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc.response["Error"].get("Message", "")):
                stacks = []
            else:
                raise
        if stacks:
            status = stacks[0]["StackStatus"]
            if status == want:
                return stacks[0]["StackId"]
            assert "FAILED" not in status and "ROLLBACK" not in status, (
                f"stack {stack!r} reached {status!r} while waiting for {want!r}; output tail: "
                f"{_log_tail(log_path)!r}"
            )
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack!r} did not reach {want!r} within {timeout_s}s; output tail: "
                f"{_log_tail(log_path)!r}"
            )
        time.sleep(poll_s)


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
    change is caught and quoted rather than missed by a single read."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        _assert_alive(proc, log_path, "the held-for window")
        seen.append(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _wait_stack_updated(cfn, stack_id: str, baseline_updated, proc, log_path: Path, *,
                        timeout_s: float, poll_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        _assert_alive(proc, log_path, "the fallback deploy to complete")
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        if status == "UPDATE_COMPLETE" and stack.get("LastUpdatedTime") != baseline_updated:
            return
        assert "FAILED" not in status and "ROLLBACK" not in status, (
            f"stack {stack_id!r} reached {status!r} while waiting for the fallback deploy; "
            f"output tail: {_log_tail(log_path)!r}"
        )
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id!r} did not update within {timeout_s}s of the Timeout edit; "
                f"output tail: {_log_tail(log_path)!r}"
            )
        time.sleep(poll_s)


def _edit_literal(app_path: Path, name: str, value: str) -> None:
    """Rewrite the ``NAME = ...`` literal assignment in *app_path* on disk, in place.

    Editing the file (not passing a new --context) is what `cdk watch`'s own file watcher reacts
    to: a new deploy it triggers itself, not one the check drives.
    """
    text = app_path.read_text()
    marker = f'"{value}"' if isinstance(value, str) and not value.isdigit() else value
    pattern = re.compile(rf"^{name} = .*$", re.MULTILINE)
    new_text, count = pattern.subn(f"{name} = {marker}", text, count=1)
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
