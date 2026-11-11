"""sns-publish-attributes-reach-subscriber-and-invalid-attribute-fails-task."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-publish-attributes-reach-subscriber-and-invalid-attribute-fails-task"
GROUP = "service-integration"
SERVICES = ["sns", "sqs", "stepfunctions"]

_TRUST_RACE_MARKERS = (
    "is not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "authorizationerror",
)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Task on arn:aws:states:::sns:publish delivers Message and MessageAttributes to a
    raw-delivery-off SQS subscriber field by field, and its output carries the MessageId SNS
    minted; an attribute whose DataType does not match its value fails the state.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-sns.html
    """
    sfn = ctx.client("stepfunctions")
    nonce = ctx.unique_name("n")[-12:]

    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    _subscribe_queue_to_topic(ctx, topic, queue)

    role_arn = _create_role(
        ctx, "states.amazonaws.com",
        {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic["arn"]},
    )
    definition = {
        "Comment": "sim2real sns:publish connector probe",
        "StartAt": "Publish",
        "States": {
            "Publish": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sns:publish",
                "Parameters": {
                    "TopicArn": topic["arn"],
                    "Message.$": "$.message",
                    "MessageAttributes.$": "$.attributes",
                },
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], definition, role_arn)

    # Beat 1 — positive control: a message with String and Number attributes is delivered to
    # the subscriber verbatim, field by field, and the Task output's MessageId matches it.
    good_message = f"control-{nonce}"
    good_attrs = {
        "kind": {"DataType": "String", "StringValue": "control"},
        "count": {"DataType": "Number", "StringValue": "7"},
    }
    good, good_exec_arn = _run_until_authorized(
        ctx, sfn, sm_arn, json.dumps({"message": good_message, "attributes": good_attrs}),
    )
    assert good["status"] == "SUCCEEDED", (
        f"the well-formed publish must succeed, got status {good['status']!r}: "
        f"{good.get('error')!r} {good.get('cause')!r}"
    )
    good_output = json.loads(good["output"])
    assert "MessageId" in good_output, f"the Task output must carry MessageId; got {good_output!r}"

    started = time.monotonic()
    delivered = _wait_for_messages(ctx, queue["url"], lambda b: b.get("Message") == good_message)
    latency_s = time.monotonic() - started
    envelope = delivered[0]
    assert envelope["MessageId"] == good_output["MessageId"], (
        f"the delivered envelope's MessageId {envelope['MessageId']!r} must match the Task "
        f"output's MessageId {good_output['MessageId']!r}"
    )
    delivered_attrs = envelope.get("MessageAttributes", {})
    expected_attrs = {
        key: {"Type": attr["DataType"], "Value": attr["StringValue"]}
        for key, attr in good_attrs.items()
    }
    assert delivered_attrs == expected_attrs, (
        f"the delivered MessageAttributes must match field by field; sent {good_attrs!r}, "
        f"expected the notification envelope {expected_attrs!r}, got {delivered_attrs!r}"
    )

    # Beat 2 — break exactly one thing: a Number attribute whose value cannot be cast to a
    # number is rejected by SNS, and the Task fails the state naming SNS's exact error.
    bad_message = f"invalid-{nonce}"
    bad_attrs = {
        "count": {"DataType": "Number", "StringValue": "not-a-number"},
    }
    bad_exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        input=json.dumps({"message": bad_message, "attributes": bad_attrs}),
    )["executionArn"]
    ctx.on_cleanup(_teardown(lambda a=bad_exec_arn: _stop_if_running(sfn, a),
                             "ExecutionDoesNotExist"))
    bad = _run_to_terminal(ctx, sfn, bad_exec_arn, timeout_s=30, interval_s=2)
    assert bad["status"] == "FAILED", (
        f"a Number attribute that cannot be cast must fail the state, got {bad['status']!r}"
    )
    assert bad["error"] == "SNS.InvalidParameterValueException", (
        f"the rejected attribute must fail with Error 'SNS.InvalidParameterValueException', "
        f"got {bad['error']!r}"
    )
    masked_cause = re.sub(r"Request ID: [^;)]+", "Request ID: <request-id>", bad["cause"])
    expected_cause = (
        "Could not cast message attribute 'count' value to number. (Service: AmazonSNS; "
        "Status Code: 400; Error Code: ParameterValueInvalid; Request ID: <request-id>; "
        "Proxy: null)"
    )
    assert masked_cause == expected_cause, (
        f"the rejected attribute's Cause did not match; expected {expected_cause!r}, "
        f"got {bad['cause']!r}"
    )

    # The rejected publish never reaches the subscriber, held over a window sized from the
    # control's measured delivery latency.
    leaked = _absent_for(
        lambda: [b for b in _drain_once(ctx, queue["url"]) if b.get("Message") == bad_message],
        latency_s,
    )
    assert leaked == [], (
        f"a rejected publish must never be delivered; the queue received {json.dumps(leaked)[:400]}"
    )


# ===== helpers =====
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it's gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=1.0,
                description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 1.0) -> list:
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _run_to_terminal(ctx, sfn, exec_arn: str, *, timeout_s: float, interval_s: float) -> dict:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"execution {exec_arn} was not terminal within {timeout_s:.0f}s: {last!r}")


def _run_until_authorized(ctx, sfn, sm_arn: str, input_str: str, max_attempts: int = 8):
    """Start an execution, retrying while an IAM grant has not yet propagated to the
    authorizer; returns ``(description, executionArn)``. A refused attempt published nothing."""
    desc = None
    exec_arn = None
    for attempt in range(max_attempts):
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)["executionArn"]
        desc = _run_to_terminal(ctx, sfn, exec_arn, timeout_s=30.0, interval_s=2.0)
        if desc["status"] == "SUCCEEDED":
            return desc, exec_arn
        blob = ((desc.get("cause") or "") + (desc.get("error") or "")).lower()
        if not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc, exec_arn
        time.sleep(5 + attempt * 3)
    raise TimeoutError(
        f"sns:Publish authorization did not propagate after {max_attempts} attempts "
        f"(last execution: {exec_arn}, status {desc['status'] if desc else 'n/a'!r})"
    )


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    name = _xname(ctx, "topic")[:80]
    arn = sns.create_topic(
        Name=name, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")[:80]
    url = sqs.create_queue(QueueName=name, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _subscribe_queue_to_topic(ctx, topic: dict[str, str], queue: dict[str, str]) -> None:
    """Grant the topic send-access, subscribe (raw delivery stays off, the default), and wait
    for the sqs-protocol subscription to leave PendingConfirmation."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue["arn"],
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}}}],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])["SubscriptionArn"]
    ctx.on_cleanup(lambda: _tolerant_unsubscribe(sns, sub_arn))
    _poll_until(
        ctx,
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn),
        lambda r: r["Attributes"].get("PendingConfirmation") == "false",
        timeout_s=30, interval_s=2, description="SNS->SQS subscription confirmed",
    )


def _tolerant_unsubscribe(sns, sub_arn: str) -> None:
    try:
        sns.unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _create_role(ctx, principal: str, statement: dict) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _delete(n=name):
        _teardown(lambda: iam.delete_role_policy(RoleName=n, PolicyName="inline"), "NoSuchEntity")()
        _teardown(lambda: iam.delete_role(RoleName=n), "NoSuchEntity")()

    ctx.on_cleanup(_delete)
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )
    return arn


def _create_state_machine(ctx, name: str, definition: dict, role_arn: str) -> str:
    """Create the machine, retrying only through the IAM role-propagation window."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": k, "value": v} for k, v in _TAGS.items()],
            )["stateMachineArn"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "AccessDeniedException":
                raise
            time.sleep(3)
            continue

        ctx.on_cleanup(_teardown(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a),
                                 "StateMachineDoesNotExist"))
        return arn
    raise TimeoutError(
        f"CreateStateMachine({name}) never succeeded within the IAM role-propagation window; "
        f"last error code {last!r}"
    )


def _drain_once(ctx, url: str) -> list:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"],
    )
    out = []
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        out.append(json.loads(msg["Body"]))
    return out


def _wait_for_messages(ctx, url: str, predicate, *, timeout_s: float = 60.0) -> list:
    """Poll SQS until a delivered envelope satisfies ``predicate``; returns every envelope
    seen that matches it (raises on timeout)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    matched: list = []
    while time.monotonic() < deadline:
        for body in _drain_once(ctx, url):
            if predicate(body):
                matched.append(body)
        if matched:
            return matched
        time.sleep(1)
    raise TimeoutError(f"no matching message arrived within {timeout_s:.0f}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
