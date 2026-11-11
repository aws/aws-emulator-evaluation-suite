"""sfn-waitfortasktoken-sqs-callback."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-waitfortasktoken-sqs-callback"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]


def _wait_execution_settled(ctx, exec_arn, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    return _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=2,
    )


def _execute_until_message(ctx, sm_arn, payload, queue_url, attempts=3):
    """Start an execution and return (execution, messages) once SQS receives the task."""
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        ex = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))
        msgs = _receive_messages(ctx, queue_url, 1, timeout_s=25, delete=False)
        if msgs:
            return ex, msgs
        time.sleep(4)
    raise AssertionError("callback task never delivered a message to SQS")


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
    """.waitForTaskToken sends $$.Task.Token to SQS and resumes on SendTaskSuccess."""
    queue = _create_queue(ctx)
    role = _create_role_stmts(
        ctx,
        "states.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]}],
        "sfn-role-token",
    )
    definition = {
        "StartAt": "Wait",
        "States": {
            "Wait": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue["url"],
                    "MessageBody": {
                        "token.$": "$$.Task.Token",
                        "job.$": "$.job",
                    },
                },
                "TimeoutSeconds": 300,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine_role(ctx, definition, role, "sm-token")

    sfn = ctx.client("stepfunctions")
    ex, msgs = _execute_until_message(ctx, sm_arn, {"job": "j-token"}, queue["url"])

    payload = msgs[0]["body"]
    assert payload["job"] == "j-token", payload
    token = payload.get("token")
    assert token, f"task token missing from callback message: {payload}"

    running = sfn.describe_execution(executionArn=ex["executionArn"])
    assert running["status"] == "RUNNING", (
        f"execution must block awaiting the callback, got {running['status']}"
    )

    sfn.send_task_success(
        taskToken=token, output=json.dumps({"result": "done", "job": "j-token"})
    )

    result = _wait_execution_settled(ctx, ex["executionArn"], timeout_s=40)
    assert result["status"] == "SUCCEEDED", result
    assert json.loads(result["output"]) == {"result": "done", "job": "j-token"}, result[
        "output"
    ]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _create_role_stmts(ctx, service_principal, statements, name_hint="role"):
    """Create a role trusting *service_principal* with an optional inline policy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_hint)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            ),
        )
        ctx.on_cleanup(
            lambda: ctx.client("iam").delete_role_policy(
                RoleName=role_name, PolicyName="inline"
            )
        )
    return role["Role"]["Arn"]


def _create_state_machine_role(ctx, definition, role_arn, name_hint="sm"):
    """Create a state machine, tolerating IAM propagation delay."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name(name_hint)

    def probe():
        try:
            return sfn.create_state_machine(
                name=sm_name, definition=json.dumps(definition), roleArn=role_arn
            )
        except ClientError:
            return None

    sm = _wait_for_effect(probe, lambda r: r is not None, timeout_s=90)
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(
            stateMachineArn=sm["stateMachineArn"]
        )
    )
    return sm["stateMachineArn"]


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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
    messages = _receive_messages(ctx, queue_url, expected_count, timeout_s=timeout_s, delete=delete)
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


def _receive_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive or the deadline passes; return what arrived."""
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
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
