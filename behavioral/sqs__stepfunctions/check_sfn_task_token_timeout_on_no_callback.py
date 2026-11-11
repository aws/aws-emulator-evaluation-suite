"""sfn-task-token-timeout-on-no-callback."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-token-timeout-on-no-callback"

GROUP = "task-token"

SERVICES = ["stepfunctions", "sqs"]


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time"
)
def run(ctx) -> None:
    """SFN waitForTaskToken times out if nobody calls SendTaskSuccess."""
    queue = _create_queue(ctx)

    sm = _create_state_machine(
        ctx,
        definition={
            "StartAt": "WaitForCallback",
            "States": {
                "WaitForCallback": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                    "Parameters": {
                        "QueueUrl": queue["url"],
                        "MessageBody": {"token.$": "$$.Task.Token"},
                    },
                    "TimeoutSeconds": 5,
                    "Catch": [{"ErrorEquals": ["States.Timeout"], "Next": "TimedOut"}],
                    "End": True,
                },
                "TimedOut": {"Type": "Succeed"},
            },
        },
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue["arn"]}],
    )
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, sm["arn"]))

    sfn = ctx.client("stepfunctions")

    # The freshly created execution role needs 15-30s to propagate. Until it
    # does, the sqs:sendMessage task fails with AccessDenied — a NON-timeout
    # error the States.Timeout Catch does not handle — so the execution ends
    # FAILED instead of exercising the timeout path under test. Retry with
    # backoff until we observe the intended SUCCEEDED-via-TimedOut outcome,
    # rather than guessing a fixed settle time up front.
    desc = None
    for attempt in range(4):
        execution = sfn.start_execution(stateMachineArn=sm["arn"], input=json.dumps({}))
        exec_arn = execution["executionArn"]
        desc = _wait_for_effect(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=30,
        )
        if desc["status"] == "SUCCEEDED":
            break
        time.sleep(15)

    assert desc["status"] == "SUCCEEDED", (
        "Expected SUCCEEDED (via Catch->TimedOut), got "
        f"{desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    # SUCCEEDED alone does not distinguish "waitForTaskToken timed out at 5s and was
    # caught into TimedOut" from a target that never honors waitForTaskToken at all and
    # just completes WaitForCallback synchronously (also SUCCEEDED, via its own End: true).
    # Require the execution's own reported elapsed time to cover most of the declared
    # TimeoutSeconds and to settle within a generous bound after it, a TaskTimedOut event in
    # the history, and the TimedOut state entered.
    elapsed = (desc["stopDate"] - desc["startDate"]).total_seconds()
    assert elapsed >= 3, (
        f"execution completed in {elapsed:.1f}s, too fast for the 5s TimeoutSeconds to "
        "have elapsed — waitForTaskToken was likely not honored"
    )
    assert elapsed < 120, f"execution took {elapsed:.1f}s to settle after a 5s timeout"

    history = sfn.get_execution_history(executionArn=exec_arn)["events"]
    timed_out = [e.get("taskTimedOutEventDetails", {}) for e in history if e["type"] == "TaskTimedOut"]
    assert [d.get("error") for d in timed_out] == ["States.Timeout"], (
        f"expected one TaskTimedOut event with error States.Timeout, got {timed_out!r}"
    )
    entered_timed_out = [
        e
        for e in history
        if e["type"] == "SucceedStateEntered"
        and e.get("stateEnteredEventDetails", {}).get("name") == "TimedOut"
    ]
    assert entered_timed_out, (
        "execution SUCCEEDED but no StateEntered(TimedOut) event in its history: "
        f"{[e['type'] for e in history]}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _stop_and_delete_state_machine(ctx, arn: str) -> None:
    """Delete a Step Functions state machine synchronously.

    A plain ``delete_state_machine`` fires and moves on, but SFN deletion is
    asynchronous: the state machine lingers in DELETING (and stays visible to the
    account audit) — indefinitely if it still has a RUNNING execution (e.g. a
    waitForTaskToken task nobody resumed). Stop any running executions first, then
    wait until the state machine is actually gone. Registered via ``on_cleanup``
    AFTER the state machine is created so LIFO runs it BEFORE the plain
    delete_state_machine teardown that ``create_state_machine`` registered.
    """
    sfn = ctx.client("stepfunctions")
    try:
        paginator = sfn.get_paginator("list_executions")
        for page in paginator.paginate(stateMachineArn=arn, statusFilter="RUNNING"):
            for ex in page.get("executions", []):
                try:
                    sfn.stop_execution(executionArn=ex["executionArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ExecutionDoesNotExist",
            "ResourceNotFound",
            "StateMachineDoesNotExist",
        ):
            raise
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    # The harness gives all cleanups 60s together; with no RUNNING execution left the
    # deletion completes on its own, so the wait stays well inside that budget.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(3)


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xsvc_tags_lower() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # IAM role trust/permission propagation has no observable signal here; the
    # caller (run()'s retry loop) already absorbs it by retrying the actual
    # role-dependent operation, so no blind pre-sleep is needed on this path.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_state_machine(ctx, definition, permissions=None) -> dict[str, str]:
    """Create a Step Functions state machine with an execution role (permissions=None → full
    access; [] → empty policy, for denial tests). Role + SM register their own teardown.
    Returns {name,arn}."""
    if permissions is None:
        statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    elif permissions:
        statements = [
            {"Effect": "Allow", "Action": p["Action"], "Resource": p["Resource"]}
            for p in permissions
        ]
    else:
        statements = []
    policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
    role = _create_role(ctx, "states.amazonaws.com", inline_policy=policy)
    name = _xname(ctx, "sm")
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role["arn"],
        type="STANDARD",
        tags=_xsvc_tags_lower(),
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
