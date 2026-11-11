"""cdk-lambda-managed-log-group-flag-update-collides-with-service-created-group-rejected."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-lambda-managed-log-group-flag-update-collides-with-service-created-group-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs"]

_DEPLOY_TIMEOUT_S = 600.0
_SYNTH_TIMEOUT_S = 240.0
_INVOKE_LOG_DEADLINE_S = 90.0
_CHANGE_SET_DEADLINE_S = 90.0
_DESTROY_TIMEOUT_S = 420.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_lambda_log_group_flag"
_FLAG = "@aws-cdk/aws-lambda:useCdkManagedLogGroup"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """With `useCdkManagedLogGroup` unset, CloudFormation never owns the function's log group, so
    enabling it on a later update collides with the group the Lambda service already created and
    CloudFormation's own change-set validation rejects the update, leaving the stack untouched.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/featureflags.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-cdkloggrp-")
    marker = ctx.unique_name("marker-")
    base = {"account": account, "region": ctx.region, "stack_name": stack, "marker": marker}
    flag_on = {**base, _FLAG: "true"}

    work = _stage_app(ctx, _APP)
    state: dict[str, Any] = {"destroyed": False, "log_group": None}

    def _cleanup() -> None:
        group = state["log_group"]
        _teardown(ctx, [] if state["destroyed"] else [stack],
                  after=[("log group", lambda: _reap_log_group(logs, group))] if group else None)

    ctx.on_cleanup(_cleanup)

    # ---- 1. the flag-enabled template is the update step 3 submits ---------------------------
    _, _, with_group = _synth_doc(ctx, work, stack, flag_on, out="out-on",
                                  timeout_s=_SYNTH_TIMEOUT_S)
    with_counts = _type_counts(with_group)
    # Precondition: without a LogGroup resource the update in step 3 would not collide at all.
    assert with_counts.get("AWS::Logs::LogGroup") == 1, (
        f"with {_FLAG}=true the template holds "
        f"{with_counts.get('AWS::Logs::LogGroup')!r} AWS::Logs::LogGroup resources, expected 1"
    )

    # ---- 2. deploy with the flag UNSET: the log group does not exist until first invoke ------
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], base,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    outputs = _stack_outputs(ctx, stack)
    function_name = outputs["FunctionName"]
    log_group_name = f"/aws/lambda/{function_name}"
    state["log_group"] = log_group_name

    # The deployed function logs to the Lambda service's default group, which nothing created.
    logging_config = lam.get_function_configuration(FunctionName=function_name)["LoggingConfig"]
    assert logging_config.get("LogGroup") == log_group_name, (
        f"GetFunctionConfiguration reports LoggingConfig {logging_config!r}, expected the "
        f"service default log group {log_group_name!r} with {_FLAG} unset"
    )
    before_invoke = _log_group(logs, log_group_name)
    assert before_invoke is None, (
        f"log group {log_group_name!r} already exists right after CREATE_COMPLETE, before any "
        f"invoke: {before_invoke!r} — with the flag unset Lambda, not CloudFormation, creates it"
    )

    invoke_1 = lam.invoke(FunctionName=function_name, Payload=b"{}")
    answered_1 = json.loads(invoke_1["Payload"].read())
    assert answered_1.get("marker") == marker, (
        f"first invoke returned {answered_1!r}, expected marker {marker!r}"
    )
    created = _wait_for_log_group(logs, log_group_name, deadline_s=_INVOKE_LOG_DEADLINE_S)
    assert created.get("retentionInDays") is None, (
        f"the Lambda-service-created log group carries retentionInDays="
        f"{created.get('retentionInDays')!r}, expected none (never-expire default)"
    )

    stack_resources = [
        resource
        for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack)
        for resource in page["StackResourceSummaries"]
    ]
    deployed_types = {resource["ResourceType"] for resource in stack_resources}
    assert "AWS::Logs::LogGroup" not in deployed_types, (
        f"the deployed stack owns a LogGroup resource ({deployed_types!r}) though its template "
        f"never declared one"
    )

    # ---- 3. BREAK EXACTLY ONE THING: ask CloudFormation to add the SAME log group it does not --
    # own, by the API the deploy tool itself drives (CreateChangeSet), never by reading CLI text.
    change_set = ctx.unique_name("sim2real-cdkloggrp-cs-")
    cfn.create_change_set(
        StackName=stack,
        ChangeSetName=change_set,
        TemplateBody=json.dumps(with_group),
        Capabilities=["CAPABILITY_IAM"],
        ChangeSetType="UPDATE",
    )
    ctx.on_cleanup(lambda: _delete_change_set(cfn, stack, change_set))
    described = _wait_for_change_set(cfn, stack, change_set, deadline_s=_CHANGE_SET_DEADLINE_S)
    assert described["Status"] == "FAILED", (
        f"CreateChangeSet for the flag-enabled template reached status {described['Status']!r}, "
        f"expected 'FAILED' — the log group {log_group_name!r} already exists outside the stack"
    )
    assert described["StatusReason"] == (
        "The following hook(s)/validation failed: [AWS::EarlyValidation::ResourceExistenceCheck]."
        " To troubleshoot Early Validation errors, use the DescribeEvents API for detailed"
        " failure information."
    ), described["StatusReason"]

    # ---- 4. the stack is untouched: a positive control proves it, in the same file -----------
    unchanged = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert unchanged["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {unchanged['StackStatus']!r} after the rejected change set, "
        f"expected CREATE_COMPLETE — a FAILED change set must never have touched the stack"
    )
    still_there = _log_group(logs, log_group_name)
    assert still_there is not None and still_there.get("retentionInDays") is None, (
        f"the log group's retention changed to {still_there!r} even though the change set that "
        f"would have set one never executed"
    )
    still_logging = lam.get_function_configuration(FunctionName=function_name)["LoggingConfig"]
    assert still_logging == logging_config, (
        f"the function's LoggingConfig moved from {logging_config!r} to {still_logging!r} though "
        f"the rejected change set never executed"
    )
    invoke_2 = lam.invoke(FunctionName=function_name, Payload=b"{}")
    answered_2 = json.loads(invoke_2["Payload"].read())
    assert answered_2.get("marker") == marker, (
        f"second invoke, after the rejected update, returned {answered_2!r}, expected marker "
        f"{marker!r} — the function itself must still work"
    )

    # ---- teardown, asserted -----------------------------------------------------------------
    _delete_change_set(cfn, stack, change_set)
    _cdk(ctx, work, ["destroy", stack, "--force"], base,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    state["destroyed"] = True
    _assert_stack_absent(ctx, stack)
    _reap_log_group(logs, log_group_name)
    state["log_group"] = None


# ===== self-contained helpers =====


def _delete_change_set(cfn, stack: str, name: str) -> None:
    try:
        cfn.delete_change_set(StackName=stack, ChangeSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ChangeSetNotFound", "ValidationError"):
            raise


def _wait_for_change_set(cfn, stack: str, name: str, *, deadline_s: float) -> dict[str, Any]:
    """Poll DescribeChangeSet to a terminal status; raise if it never settles."""
    deadline = time.monotonic() + deadline_s
    described: dict[str, Any] = {}
    while time.monotonic() < deadline:
        described = cfn.describe_change_set(StackName=stack, ChangeSetName=name)
        if described["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return described
        time.sleep(3.0)
    raise AssertionError(
        f"change set {name!r} on {stack!r} did not reach a terminal status within "
        f"{deadline_s}s; last seen {described.get('Status')!r}"
    )


def _log_group(logs, name: str) -> dict[str, Any] | None:
    groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    for group in groups:
        if group["logGroupName"] == name:
            return group
    return None


def _wait_for_log_group(logs, name: str, *, deadline_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        group = _log_group(logs, name)
        if group is not None:
            return group
        time.sleep(3.0)
    raise AssertionError(f"log group {name!r} never appeared within {deadline_s}s of the invoke")


def _teardown(ctx, stacks: list[str], after: list[tuple[str, Any]] | None = None) -> None:
    """Delete each stack this run created, then run each after step; raise every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = [
        (f"stack {stack}", lambda s=stack: _delete_stack_and_wait(
            ctx, s, timeout_s=max(30.0, deadline - time.monotonic())))
        for stack in stacks
    ]
    steps += list(after or [])
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - every step runs; the failures are raised below
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
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
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


def _type_counts(template: dict[str, Any]) -> dict[str, int]:
    """How many resources of each type the template declares."""
    counts: dict[str, int] = {}
    for resource in template["Resources"].values():
        counts[resource["Type"]] = counts.get(resource["Type"], 0) + 1
    return counts


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
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


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-notices", "--no-version-reporting", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _synth_doc(ctx, work: Path, stack: str, context: dict[str, str], *, out: str,
               timeout_s: float) -> tuple[int, str, dict[str, Any]]:
    """Synthesise into `<work>/<out>`, asserting exit 0; return `(rc, output, parsed template)`."""
    shutil.rmtree(work / out, ignore_errors=True)
    rc, output = _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
                      timeout_s=timeout_s, expect_rc=0)
    template = work / out / f"{stack}.template.json"
    assert template.is_file(), (
        f"`cdk synth` exited {rc} but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return rc, output, json.loads(template.read_text())


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's own record."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _assert_stack_absent(ctx, stack: str) -> None:
    """An independent read must report the stack gone with CloudFormation's specific code."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the deleted stack {stack!r} returned error code {code!r}, expected "
        f"'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on the deleted stack {stack!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
