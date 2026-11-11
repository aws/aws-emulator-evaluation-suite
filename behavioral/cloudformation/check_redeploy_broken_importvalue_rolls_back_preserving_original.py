"""redeploy-broken-importvalue-rolls-back-preserving-original."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "redeploy-broken-importvalue-rolls-back-preserving-original"
GROUP = "cli-roundtrip"
SERVICES = ["cloudformation"]

_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second `aws cloudformation deploy` adding a resource whose tag imports a never-declared
    export exits non-zero and rolls the stack back, naming the missing export, with the original
    resource untouched and the new one never created; a third, valid deploy still succeeds."""
    require_tools("aws")

    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-behav-redeploybad-")
    q1 = ctx.unique_name("sim2real-behav-redeploybad-q1-")
    q2 = ctx.unique_name("sim2real-behav-redeploybad-q2-")
    bogus_export = ctx.unique_name("sim2real-behav-redeploybad-no-such-export-")

    v1 = _write_template(_template({"Q1": q1}))
    ctx.on_cleanup(lambda: os.unlink(v1) if os.path.exists(v1) else None)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _deploy(ctx, stack_name, v1)
    status = _stack_status(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"first deploy: expected CREATE_COMPLETE, got {status!r}"
    q1_url = sqs.get_queue_url(QueueName=q1)["QueueUrl"]

    # Break exactly one thing: Q2's tag imports an export nothing ever published.
    v2_broken = _write_template(_template({"Q1": q1, "Q2": q2}, import_export=bogus_export))
    try:
        rc, stderr = _deploy_allow_failure(ctx, stack_name, v2_broken)
    finally:
        os.unlink(v2_broken)
    assert rc != 0, f"expected `aws cloudformation deploy` to fail, it exited 0: {stderr[-400:]}"

    status = _wait_terminal(cfn, stack_name, _UPDATE_TERMINAL, timeout_s=300.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"broken import update: expected UPDATE_ROLLBACK_COMPLETE, got {status!r}"
    )
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    expected_reason = f"No export named {bogus_export} found"
    naming = [e for e in events if e.get("ResourceStatusReason") == expected_reason]
    assert naming, (
        f"expected a stack event whose reason is exactly {expected_reason!r}, got "
        f"{[(e['LogicalResourceId'], e['ResourceStatus'], e.get('ResourceStatusReason')) for e in events]!r}"
    )

    # (b) the effect is absent: Q2 was never created.
    code, msg = _error_code_and_message(lambda: sqs.get_queue_url(QueueName=q2))
    assert (code, msg) == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"Q2 should never have been created, got ({code!r}, {msg!r})"
    )
    # Q1 (the original resource) is untouched by the failed update.
    assert sqs.get_queue_url(QueueName=q1)["QueueUrl"] == q1_url, (
        "Q1's URL changed across the rolled-back redeploy"
    )
    resources = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    }
    # Q2's own attempted Add is what rolled back; Q1 was never touched by this update, so it
    # keeps its prior CREATE_COMPLETE status rather than acquiring an UPDATE_ROLLBACK status.
    assert resources == {"Q1": "CREATE_COMPLETE"}, (
        f"expected only Q1, still CREATE_COMPLETE (untouched by the rolled-back update), "
        f"got {resources!r}"
    )

    # (c) positive control, same file: a valid change still deploys after the rollback.
    v3_fixed = _write_template(_template({"Q1": q1, "Q2": q2}))
    try:
        _deploy(ctx, stack_name, v3_fixed)
    finally:
        os.unlink(v3_fixed)
    status = _stack_status(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"control deploy: expected UPDATE_COMPLETE, got {status!r}"
    sqs.get_queue_url(QueueName=q2)  # raises if Q2 still doesn't exist

    _delete_stack(cfn, stack_name)
    got = _error_code_and_message(lambda: cfn.describe_stacks(StackName=stack_name))
    assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks after the in-band delete: {got!r}"
    )
    for name in (q1, q2):
        got = _error_code_and_message(lambda name=name: sqs.get_queue_url(QueueName=name))
        assert got == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
            f"queue {name} after the stack delete: {got!r}"
        )


def _template(queues: dict, *, import_export: str | None = None) -> str:
    resources = {}
    for logical, name in queues.items():
        props = {"QueueName": name}
        if import_export is not None and logical == "Q2":
            props["Tags"] = [{"Key": "Src", "Value": {"Fn::ImportValue": import_export}}]
        resources[logical] = {"Type": "AWS::SQS::Queue", "Properties": props}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _write_template(body: str) -> str:
    fd, path = tempfile.mkstemp(prefix="sim2real-redeploybad-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    return path


def _deploy(ctx, stack_name: str, template_path: str, timeout_s: float = 300.0) -> None:
    ctx.verify_account_safety()
    result = subprocess.run(
        ["aws", "cloudformation", "deploy", "--stack-name", stack_name,
         "--template-file", template_path],
        env=ctx.subprocess_env(), capture_output=True, text=True, timeout=timeout_s,
    )
    assert result.returncode == 0, (
        f"`aws cloudformation deploy` failed (rc={result.returncode}): {result.stderr[-800:]}"
    )


def _deploy_allow_failure(ctx, stack_name: str, template_path: str, timeout_s: float = 300.0):
    ctx.verify_account_safety()
    result = subprocess.run(
        ["aws", "cloudformation", "deploy", "--stack-name", stack_name,
         "--template-file", template_path],
        env=ctx.subprocess_env(), capture_output=True, text=True, timeout=timeout_s,
    )
    return result.returncode, result.stderr


def _stack_status(cfn, name: str) -> str:
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _wait_terminal(cfn, name: str, terminal, timeout_s: float = 180.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = _stack_status(cfn, name)
        except ClientError as exc:
            if "does not exist" in str(exc) and "DELETE_COMPLETE" in terminal:
                return "DELETE_COMPLETE"
            raise
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} did not reach {terminal} within {timeout_s}s (last={last!r})")


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("the call succeeded; expected it to be rejected")


def _delete_stack(cfn, name: str) -> None:
    try:
        status = _stack_status(cfn, name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=name)
    final = _wait_terminal(cfn, name, _DELETE_TERMINAL, timeout_s=300.0)
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {name} did not reach DELETE_COMPLETE: {final!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
