"""sfn-wait-for-task-token-lambda-resumes."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-wait-for-task-token-lambda-resumes"

GROUP = "task-token"

SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SFN pauses on an SQS waitForTaskToken task; the check reads the token from the queue,
    calls SendTaskSuccess, and the execution resumes and succeeds with the callback output."""
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
                        "MessageBody": {
                            "token.$": "$$.Task.Token",
                            "order_id.$": "$.order_id",
                        },
                    },
                    "ResultPath": "$.callback_result",
                    "Next": "Done",
                },
                "Done": {"Type": "Succeed"},
            },
        },
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue["arn"]}],
    )
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, sm["arn"]))

    sfn = ctx.client("stepfunctions")

    # The state machine's freshly created execution role can take 15-30s to
    # propagate. Until it does, the sqs:sendMessage.waitForTaskToken task fails
    # before it can emit the token, so the message never lands on the queue.
    # Retry the whole execution until the token message arrives, giving IAM
    # time to settle between attempts.
    messages = None
    exec_arn = None
    for attempt in range(4):
        execution = sfn.start_execution(
            stateMachineArn=sm["arn"],
            input=json.dumps({"order_id": "token-test-001"}),
        )
        exec_arn = execution["executionArn"]
        try:
            messages = _wait_for_messages(
                ctx, queue["url"], expected_count=1, timeout_s=45, delete=False
            )
            break
        except AssertionError:
            time.sleep(10 + attempt * 5)
    assert messages, (
        "Task token message not received in SQS after retries (execution likely failed before SendMessage while the role propagated)"
    )
    body = messages[0]["body"]
    if isinstance(body, str):
        body = json.loads(body)
    token = body["token"]
    assert token, "Task token not received in SQS message"

    sfn.send_task_success(
        taskToken=token, output=json.dumps({"completed_by": "lambda"})
    )

    desc = _wait_for_effect(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=30,
    )
    assert desc["status"] == "SUCCEEDED"
    output = json.loads(desc["output"])
    assert output.get("callback_result", {}).get("completed_by") == "lambda"


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
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(2)
    raise RuntimeError(f"state machine {arn} still exists 90 s after delete_state_machine")


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
    # No blanket sleep here: IAM role trust/permission propagation is bounded
    # by the caller's own retry-with-backoff loop around the first use of this
    # role (see `run`), which already states that reason and has a deadline.
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


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


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
