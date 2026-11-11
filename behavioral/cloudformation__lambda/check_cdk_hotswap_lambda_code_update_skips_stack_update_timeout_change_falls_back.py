"""cdk-hotswap-lambda-code-update-skips-stack-update-timeout-change-falls-back."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-hotswap-lambda-code-update-skips-stack-update-timeout-change-falls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_LOG_REAP_BUDGET_S = 180.0

_APP = "cdk_hotswap_fn"
_STACK_RESOURCE_TYPE = "AWS::CloudFormation::Stack"
_FUNCTION_RESOURCE_TYPE = "AWS::Lambda::Function"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """`cdk deploy --hotswap-fallback` of a Lambda code-only change touches neither a stack event
    nor LastUpdatedTime, but the same command for a Timeout change is rejected as non-hotswappable
    and falls back to a full deployment that updates both the function and the stack.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-deploy.html#ref-cli-cmd-deploy-options-hotswap-fallback
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    stack = ctx.unique_name("sim2real-cdkhotswap-")
    base = {"account": account, "region": ctx.region, "stack_name": stack}
    marker1 = ctx.unique_name("m1-")
    marker2 = ctx.unique_name("m2-")

    work = _stage_app(ctx, _APP)
    fn_name: str | None = None

    try:
        # ---- 1. baseline: an ordinary deploy creates the stack ---------------------------------
        _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
             {**base, "marker": marker1, "timeout": "10"},
             timeout_s=_DEPLOY_TIMEOUT_S)
        created = _describe_stack(cfn, stack)
        assert created["StackStatus"] == "CREATE_COMPLETE", (
            f"stack {stack!r} is {created['StackStatus']!r} right after its first deploy, "
            f"expected CREATE_COMPLETE"
        )
        fn_name = {o["OutputKey"]: o["OutputValue"]
                   for o in created.get("Outputs", [])}["FunctionName"]
        baseline_updated = created.get("LastUpdatedTime")
        baseline_events = _stack_level_events(cfn, stack)

        config1 = _function_config(lam, fn_name)
        code1 = config1["CodeSha256"]
        timeout1 = config1["Timeout"]
        assert timeout1 == 10, (
            f"freshly deployed function {fn_name!r} reports Timeout {timeout1!r}, expected 10"
        )
        payload1 = _invoke(lam, fn_name)
        assert payload1 == {"marker": marker1}, (
            f"invoke of the freshly deployed function returned {payload1!r}, expected "
            f"{{'marker': {marker1!r}}}"
        )

        # ---- 2. HOTSWAP: a code-only change updates the function, not the stack ----------------
        _cdk(ctx, work, ["deploy", stack, "--hotswap-fallback", "--require-approval", "never"],
             {**base, "marker": marker2, "timeout": "10"},
             timeout_s=_DEPLOY_TIMEOUT_S)

        config2 = _function_config(lam, fn_name)
        assert config2["CodeSha256"] != code1, (
            f"CodeSha256 is still {config2['CodeSha256']!r} after a hotswapped code change — "
            f"the function's code was not actually updated"
        )
        payload2 = _invoke(lam, fn_name)
        assert payload2 == {"marker": marker2}, (
            f"after the hotswap, invoke returned {payload2!r}, expected "
            f"{{'marker': {marker2!r}}} — the hotswapped code did not take effect"
        )
        assert config2["Timeout"] == 10, (
            f"Timeout changed to {config2['Timeout']!r} from a hotswap deploy that changed only "
            f"the code"
        )

        after_hotswap = _describe_stack(cfn, stack)
        assert after_hotswap["StackStatus"] == "CREATE_COMPLETE", (
            f"stack {stack!r} is {after_hotswap['StackStatus']!r} after a hotswapped deploy, "
            f"expected it to stay CREATE_COMPLETE — a hotswap must not touch the stack"
        )
        assert after_hotswap.get("LastUpdatedTime") == baseline_updated, (
            f"stack {stack!r}'s LastUpdatedTime moved from {baseline_updated!r} to "
            f"{after_hotswap.get('LastUpdatedTime')!r} after a hotswapped deploy"
        )
        events_after_hotswap = _stack_level_events(cfn, stack)
        fn_events_after_hotswap = _stack_level_events(cfn, stack, _FUNCTION_RESOURCE_TYPE)
        assert events_after_hotswap == baseline_events, (
            f"stack-level events changed from {baseline_events!r} to {events_after_hotswap!r} "
            f"after a hotswapped deploy — hotswap must not produce any CloudFormation stack event"
        )

        # ---- 3. FALLBACK: a Timeout change is rejected as non-hotswappable ---------------------
        _cdk(ctx, work, ["deploy", stack, "--hotswap-fallback", "--require-approval", "never"],
             {**base, "marker": marker2, "timeout": "20"},
             timeout_s=_DEPLOY_TIMEOUT_S)

        config3 = _function_config(lam, fn_name)
        payload3 = _invoke(lam, fn_name)
        assert payload3 == {"marker": marker2}, (
            f"after the fallback deploy, invoke returned {payload3!r}, expected the unchanged "
            f"marker {{'marker': {marker2!r}}}"
        )
        assert config3["Timeout"] == 20, (
            f"the function's Timeout is {config3['Timeout']!r} after the fallback deploy, "
            f"expected 20 — the rejected property was never actually applied"
        )

        after_fallback = _describe_stack(cfn, stack)
        assert after_fallback["StackStatus"] == "UPDATE_COMPLETE", (
            f"stack {stack!r} is {after_fallback['StackStatus']!r} after the fallback deploy, "
            f"expected UPDATE_COMPLETE — a non-hotswappable change must be reconciled through a "
            f"full CloudFormation deployment"
        )
        assert after_fallback.get("LastUpdatedTime") != baseline_updated, (
            f"stack {stack!r}'s LastUpdatedTime is still {after_fallback.get('LastUpdatedTime')!r} "
            f"after a full fallback deployment, expected it to move past {baseline_updated!r}"
        )
        events_after_fallback = _stack_level_events(cfn, stack)
        new_events = [e for e in events_after_fallback if e not in events_after_hotswap]
        new_statuses = {status for _, status in new_events}
        assert "UPDATE_COMPLETE" in new_statuses, (
            f"no new UPDATE_COMPLETE stack-level event appeared after the fallback deploy; new "
            f"stack-level events were {new_events!r} — a non-hotswappable change must be carried "
            f"out as a real CloudFormation deployment, not another hotswap"
        )
        fn_events_after_fallback = _stack_level_events(cfn, stack, _FUNCTION_RESOURCE_TYPE)
        new_fn_statuses = {status for e_id, status in fn_events_after_fallback
                           if (e_id, status) not in fn_events_after_hotswap}
        assert "UPDATE_COMPLETE" in new_fn_statuses, (
            f"no new UPDATE_COMPLETE event on the {_FUNCTION_RESOURCE_TYPE} resource appeared "
            f"after the fallback deploy; new statuses were {sorted(new_fn_statuses)!r} — the "
            f"Timeout change must be applied to the function through CloudFormation"
        )
    finally:
        _teardown(ctx, stack, fn_name)


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo.

    A missing app directory fails the check rather than being created."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float) -> None:
    """Run the CDK CLI in *work* and assert it exits 0.

    `--no-version-reporting` drops CDK metadata, `--no-notices` skips the notices fetch, and
    `--no-color` keeps ANSI out of the failure output."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"`cdk {' '.join(args)}` exited {result.returncode}, expected 0; output "
        f"tail: {output[-1200:]!r}"
    )


def _describe_stack(cfn, stack: str) -> dict:
    return cfn.describe_stacks(StackName=stack)["Stacks"][0]


def _stack_level_events(cfn, stack: str,
                        resource_type: str = _STACK_RESOURCE_TYPE) -> list[tuple[str, str]]:
    """`(EventId, ResourceStatus)` for every event CloudFormation recorded against resources of
    *resource_type* (by default the stack resource itself), newest first."""
    events: list[tuple[str, str]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for e in page["StackEvents"]:
            if e["ResourceType"] == resource_type:
                events.append((e["EventId"], e["ResourceStatus"]))
    return events


def _function_config(lam, fn_name: str) -> dict:
    return lam.get_function(FunctionName=fn_name)["Configuration"]


def _invoke(lam, fn_name: str) -> dict:
    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    assert "FunctionError" not in resp, (
        f"invoke of {fn_name!r} errored: {resp['Payload'].read()[:400]!r}"
    )
    return json.loads(resp["Payload"].read())


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    """Delete, then poll to DELETE_COMPLETE (DELETE_FAILED is not accepted); raises on timeout."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent.

    A buffered log stream from an already-returned invoke can flush after the delete and recreate
    the group, so one `delete_log_group` is one round, not a teardown."""
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


def _teardown(ctx, stack: str, fn_name: str | None) -> None:
    """Delete the stack, then reap the log group Lambda created on invoke (the stack never owns
    it). Either step's own failure propagates rather than being hidden."""
    _delete_stack_and_wait(ctx, stack, timeout_s=_TEARDOWN_DEADLINE_S)
    if fn_name:
        _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn_name}", budget_s=_LOG_REAP_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
