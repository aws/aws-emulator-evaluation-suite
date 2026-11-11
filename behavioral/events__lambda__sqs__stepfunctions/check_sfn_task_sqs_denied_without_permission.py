"""sfn-task-sqs-denied-without-permission."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-sqs-denied-without-permission"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]


def _drain(ctx, queue_url, rounds=8):
    """Collect and delete messages arriving during a settle window using SQS long polling.
    Deletes what it finds so a stray delivery from this phase cannot resurface and contaminate
    a later read of the same queue."""
    sqs = ctx.client("sqs")
    collected = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        msgs = resp.get("Messages", [])
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        collected.extend(msgs)
    return collected


def _wait_execution_settled(ctx, exec_arn, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    return _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=2,
    )


def _is_assume_role_lag(desc):
    """True when the execution failed only because role trust had not propagated."""
    return desc["status"] == "FAILED" and "not authorized to assume" in str(
        desc.get("cause", "")
    )


def _execute(ctx, sm_arn, payload, timeout_s=30.0):
    """Run an execution to completion, retrying past IAM trust propagation lag."""
    sfn = ctx.client("stepfunctions")
    desc = None
    deadline = time.monotonic() + timeout_s
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        ex = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))
        desc = _wait_execution_settled(ctx, ex["executionArn"], timeout_s=40)
        if not _is_assume_role_lag(desc) or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert desc is not None and not _is_assume_role_lag(desc), (
        f"state machine role never became assumable: {desc}"
    )
    return desc


def _execute_until_status(ctx, sm_arn, make_payload, want_status, timeout_s=60, interval_s=5):
    """Retry executions on the same wiring until one reaches want_status, bounded by timeout_s.
    Each attempt gets its own payload from make_payload(attempt_index), so a caller can tell
    which attempt produced the returned outcome.

    IAM policy changes have no pollable "is this effective yet" signal, so the wait is on the
    actual downstream action (an execution) rather than a blind sleep. Confirmed on real AWS:
    revoking an inline policy is NOT instant for a role a state machine already holds -- the
    first two attempts after delete_role_policy still succeeded and delivered before the third
    one failed. So the caller must not assume "no delivery from any attempt", only "no delivery
    from the attempt that actually reached want_status".

    Returns (desc, payload) for the attempt that decided the outcome (either the first to match
    want_status, or the last one tried before the deadline -- so a target that never reaches
    want_status still fails the caller's assertion with the real outcome, not a swallowed
    timeout).
    """
    deadline = time.monotonic() + timeout_s
    attempt = 0
    payload = make_payload(attempt)
    desc = _execute(ctx, sm_arn, payload)
    while desc["status"] != want_status and time.monotonic() < deadline:
        time.sleep(interval_s)
        attempt += 1
        payload = make_payload(attempt)
        desc = _execute(ctx, sm_arn, payload)
    return desc, payload


@tags("axis:negative-delivery", "cap:c3", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """sqs:sendMessage task requires sqs:SendMessage on the assumed role: granted, it delivers;
    revoked on the identical wiring, it FAILS and delivers nothing; re-granted, it delivers again."""
    iam = ctx.client("iam")
    queue = _create_queue(ctx)
    send_stmt = [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]}]
    role = _create_role_stmts(ctx, "states.amazonaws.com", send_stmt, "sfn-role-sqs")
    definition = {
        "StartAt": "Send",
        "States": {
            "Send": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {
                    "QueueUrl": queue["url"],
                    "MessageBody.$": "$.payload",
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine_role(ctx, definition, role["arn"], "sm-sqs")

    # Positive control: the grant is real before anything is broken. Without this, a target that
    # denies every sqs:sendMessage task -- not just unpermissioned ones -- would pass identically.
    granted, granted_payload = _execute_until_status(
        ctx, sm_arn, lambda i: {"payload": f"control-granted-{i}"}, "SUCCEEDED"
    )
    assert granted["status"] == "SUCCEEDED", (
        f"sqs:SendMessage is granted, so the task must succeed before anything is broken: {granted}"
    )
    control_msgs = _wait_for_messages(ctx, queue["url"], 1, timeout_s=60)
    assert control_msgs[0]["body"] == granted_payload["payload"], control_msgs[0]

    # Break exactly one thing: revoke sqs:SendMessage from the same role.
    iam.delete_role_policy(RoleName=role["name"], PolicyName="inline")

    denied, denied_payload = _execute_until_status(
        ctx, sm_arn, lambda i: {"payload": f"should-not-arrive-{i}"}, "FAILED"
    )
    assert denied["status"] == "FAILED", (
        f"execution succeeded without sqs:SendMessage -- overly permissive: {denied}"
    )

    # Ground truth on real AWS: a role with no SQS grant yields
    # error="SQS.AmazonSQSException" with cause "The security token included in
    # the request is invalid." Other accounts/paths surface AccessDenied.
    blob = json.dumps(denied, default=str)
    assert any(
        marker in blob
        for marker in (
            "AccessDenied",
            "AmazonSQSException",
            "security token",
            "not authorized",
        )
    ), f"failure was not attributable to the missing SQS permission: {blob[:600]}"

    # Ground truth on real AWS: revoking an inline policy is NOT instant for a role a state
    # machine already holds -- retries before the final FAILED one can still succeed and
    # deliver while the revocation propagates. That lag is real IAM eventual consistency, not an
    # overly-permissive target, so only the attempt that actually FAILED must have delivered
    # nothing; earlier attempts' deliveries are drained and discarded, not asserted against.
    extra = _drain(ctx, queue["url"], rounds=4)
    leaked = [m for m in extra if m.get("Body") == denied_payload["payload"]]
    assert not leaked, (
        f"message delivered for the execution that itself FAILED -- delivery outran the state "
        f"machine's own denial: {leaked}"
    )

    # Restore: re-grant the identical policy on the identical wiring, and demand delivery resumes.
    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": send_stmt}),
    )

    restored, restored_payload = _execute_until_status(
        ctx, sm_arn, lambda i: {"payload": f"control-restored-{i}"}, "SUCCEEDED"
    )
    assert restored["status"] == "SUCCEEDED", (
        f"re-granting sqs:SendMessage must restore delivery on the identical wiring: {restored}"
    )
    restored_msgs = _wait_for_messages(ctx, queue["url"], 1, timeout_s=60)
    assert restored_msgs[0]["body"] == restored_payload["payload"], restored_msgs[0]


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _create_role_stmts(ctx, service_principal, statements, name_hint="role"):
    """Create a role trusting *service_principal* with an optional inline policy named "inline".
    Returns {"name": role_name, "arn": role_arn}."""
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
        ctx.on_cleanup(lambda: _delete_role_policy_best_effort(ctx, role_name, "inline"))
    return {"name": role_name, "arn": role["Role"]["Arn"]}


def _delete_role_policy_best_effort(ctx, role_name, policy_name):
    """Teardown-only: the body itself deletes and re-creates this policy, so tolerate it already
    being gone at cleanup time."""
    try:
        ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
