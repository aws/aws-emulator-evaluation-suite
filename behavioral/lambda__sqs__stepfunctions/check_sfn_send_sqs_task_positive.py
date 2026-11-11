"""sfn-send-sqs-task-positive."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sfn-send-sqs-task-positive"

GROUP = "event-propagation"

SERVICES = ["lambda", "stepfunctions", "sqs"]

_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _get_body(msg: dict):
    """Extract message body regardless of key casing (Body vs body). Returns str or dict."""
    raw = msg.get("Body") or msg.get("body")
    if raw is None:
        return ""
    return raw


def _body_str(msg: dict) -> str:
    """Extract message body as string (JSON-encode if already a dict)."""
    raw = _get_body(msg)
    if isinstance(raw, dict):
        return json.dumps(raw)
    return str(raw) if raw is not None else ""


def _msgs_list(raw) -> list:
    """Normalize wait_for_messages result: accepts list-of-dicts or raw SQS response dict."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return raw.get("Messages") or raw.get("messages") or []
    return []


def _run_sfn_until_trust_propagated(
    sfn, sm_arn: str, input_str: str, max_attempts: int = 8
):
    """Start an execution, retrying only while it fails on the IAM-trust race.

    Returns the terminal describe_execution dict. Raises AssertionError only if the
    trust never propagates within the budget (a genuine, reportable condition).
    """
    desc = None
    for attempt in range(max_attempts):
        execution = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)
        exec_arn = execution["executionArn"]
        desc = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
            timeout_s=30,
            interval_s=3,
        )
        if desc["status"] != "FAILED":
            return desc
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in cause for m in _TRUST_RACE_MARKERS):
            # A real failure (not the trust race) — return it for the check to assert on.
            return desc
        # Trust race: back off and retry with a fresh execution.
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"Step Functions role trust did not propagate after {max_attempts} attempts "
        f"(last cause: {desc.get('cause') if desc else 'n/a'})"
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Step Functions Task state sends a message to SQS using optimized integration."""
    queue = _create_queue(ctx)

    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sfn-sqs-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=_xsvc_tags_kv()
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sqs:SendMessage",
                    "Resource": queue["arn"],
                }
            ],
        }
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sqs-send", PolicyDocument=policy_doc
    )
    # Wait for IAM policy to be readable (propagation signal)
    _poll_until(
        lambda: iam.get_role_policy(RoleName=role_name, PolicyName="sqs-send"),
        lambda r: "PolicyDocument" in r,
        timeout_s=30,
        interval_s=2,
    )

    sm_name = ctx.unique_name("sm-sqs-")
    definition = json.dumps(
        {
            "StartAt": "SendToSQS",
            "States": {
                "SendToSQS": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": queue["url"],
                        "MessageBody.$": "$.message",
                    },
                    "End": True,
                }
            },
        }
    )
    sm = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=role_arn,
        tags=_xsvc_tags_lower(),
    )
    sm_arn = sm["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=sm_arn)
    )

    status = _run_sfn_until_trust_propagated(
        sfn, sm_arn, json.dumps({"message": "sfn-direct-sqs"})
    )["status"]

    assert status == "SUCCEEDED", f"Expected SUCCEEDED, got: {status}"

    msgs = _msgs_list(
        _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=30)
    )
    assert msgs, "No messages in SQS queue"
    assert _body_str(msgs[0]) == "sfn-direct-sqs", (
        f"Expected 'sfn-direct-sqs', got: {_body_str(msgs[0])}"
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
