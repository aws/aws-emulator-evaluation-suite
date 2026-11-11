"""pipes-sqs-source-starts-sfn-target-execution."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-sqs-source-starts-sfn-target-execution"

GROUP = "event-propagation"

SERVICES = ["pipes", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe with an SQS source and a Step Functions target starts an execution whose input is
    the SQS source record (body, messageId, eventSourceARN), not a re-wrapped envelope.
    """
    sqs = ctx.client("sqs")
    source = _create_queue(ctx)

    # A Pass state: no permissions needed, and its output echoes its input, so the assertion is
    # purely about what Pipes handed the state machine.
    sm = _create_state_machine(
        ctx,
        definition={"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}},
        permissions=[],
    )

    pipe_role = _create_role(
        ctx,
        "pipes.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                    ],
                    "Resource": source["arn"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["states:StartExecution"],
                    "Resource": sm["arn"],
                },
            ],
        },
    )

    marker = _xname(ctx, "smark")
    _create_pipe(
        ctx,
        source=source["arn"],
        target=sm["arn"],
        role_arn=pipe_role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        # FIRE_AND_FORGET is mandatory for a STANDARD state machine target; REQUEST_RESPONSE is
        # only valid for EXPRESS. Getting this wrong is a create-time ValidationException, so a
        # RUNNING pipe proves the emulator at least validated the target parameters.
        TargetParameters={
            "StepFunctionStateMachineParameters": {"InvocationType": "FIRE_AND_FORGET"}
        },
    )

    sent = sqs.send_message(
        QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker})
    )

    # The message is durable on the queue, so the pipe poller will pick it up whenever it comes
    # up; no re-trigger is needed (unlike EventBridge rules, which drop events fired too early).
    # 300s: Pipes' first poll after CurrentState==RUNNING is minutes-scale on real AWS.
    execution = _first_execution(
        ctx, sm["arn"], trigger=lambda: None, timeout_s=300, interval_s=10.0
    )
    desc = _wait_execution_terminal(ctx, execution["executionArn"], timeout_s=90)
    assert desc["status"] == "SUCCEEDED", (
        f"pipe-started execution did not succeed: {desc['status']} {desc.get('cause')}"
    )

    payload = json.loads(desc["input"])
    # Pipes delivers a LIST of source records (batch), even at BatchSize 1.
    records = payload if isinstance(payload, list) else [payload]
    assert len(records) == 1, (
        f"SqsQueueParameters.BatchSize=1 not honoured; execution input carried "
        f"{len(records)} records: {records!r}"
    )
    record = records[0]
    assert record.get("messageId") == sent["MessageId"], (
        f"source messageId not preserved into the SFN execution input: "
        f"{record.get('messageId')!r} != {sent['MessageId']!r}"
    )
    assert record.get("eventSourceARN") == source["arn"], (
        f"eventSourceARN wrong: {record.get('eventSourceARN')!r} != {source['arn']!r}"
    )
    # SQS bodies stay strings through Pipes when there is no input template.
    assert json.loads(record["body"]) == {"marker": marker}, (
        f"source body mangled on the way to the SFN target: {record.get('body')!r}"
    )
    assert json.loads(desc["output"]) == payload, (
        f"Pass state output diverged from the pipe-supplied input: {desc['output']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


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
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _is_role_propagation_error(exc: ClientError) -> bool:
    """True for the transient assume-role failures IAM trust/permission propagation causes."""
    msg = str(exc)
    return (
        "cannot be assumed" in msg
        or "is not authorized to assume" in msg
        or "iam:PassRole" in msg
        or "InvalidParameterValueException" in msg
        or "AccessDeniedException" in msg
    )


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
    last_err = None
    arn = None
    for _ in range(8):
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role["arn"],
                type="STANDARD",
                tags=_xsvc_tags_lower(),
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if _is_role_propagation_error(exc):
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create state machine {name}: {last_err}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, arn))
    return {"name": name, "arn": arn}


def _stop_and_delete_state_machine(ctx, arn: str) -> None:
    """Stop running executions, delete the state machine and wait until it is gone.

    SFN deletion is asynchronous and a state machine with a RUNNING execution stays DELETING.
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
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"state machine {arn} still exists 90 s after DeleteStateMachine")


def _first_execution(ctx, sm_arn, *, trigger, timeout_s=180.0, interval_s=5.0):
    """Call trigger() each poll until the state machine has >=1 execution; return the first one.

    Target wiring is not live the instant create returns; extra executions are harmless.
    """
    sfn = ctx.client("stepfunctions")

    def _probe():
        trigger()
        return sfn.list_executions(stateMachineArn=sm_arn, maxResults=5).get(
            "executions", []
        )

    execs = _poll_until(
        _probe,
        lambda e: len(e) > 0,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"execution of {sm_arn}",
    )
    return execs[0]


def _wait_execution_terminal(ctx, exec_arn, *, timeout_s=90.0):
    """Poll describe_execution until the execution reaches a terminal status; return the response."""
    sfn = ctx.client("stepfunctions")
    return _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"]
        in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"execution {exec_arn} terminal",
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, **extra) -> dict[str, str]:
    """Create a pipe and wait for CurrentState==RUNNING (registers delete_pipe).

    Pipes assumes the role at create time, so a fresh role is retried until IAM propagates.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(8):
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            if _is_role_propagation_error(exc) or "ValidationException" in str(exc):
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == "RUNNING",
        timeout_s=180,
        interval_s=5.0,
        description=f"pipe {name} RUNNING",
    )
    return {"name": name}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
