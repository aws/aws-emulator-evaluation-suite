"""cfn-notification-arns-publish-every-stack-event."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-notification-arns-publish-every-stack-event"
GROUP = "eventing"
SERVICES = ["cloudformation", "sns", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
STACK_TIMEOUT_S = 240.0
DELIVERY_TIMEOUT_S = 180.0
_KV = re.compile(r"^([A-Za-z]+)='(.*)'$")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """A stack created with NotificationARNs must publish its real stack events to the topic, and a
    stack created without them must publish nothing."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    template = (DEPLOYMENTS / "notified-stack.yaml").read_text()

    # --- Consumer wiring, created in-check ------------------------------------------------------
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cfn-notif-t-"), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cfn-notif-q-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub_arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        # Raw delivery so the queue body is CloudFormation's own notification text rather than an
        # SNS envelope wrapping it; the envelope is a separate service's contract, tested elsewhere.
        Attributes={"RawMessageDelivery": "true"},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))

    # --- The subject: a stack that names the topic ------------------------------------------------
    token = ctx.unique_name("sim2realcfnnotiftok-")
    subject = ctx.unique_name("sim2real-cfn-notif-s-")
    param_name = "/" + ctx.unique_name("sim2real-cfn-notif-p-")
    param_value = ctx.unique_name("notified-")
    stack_id = cfn.create_stack(
        StackName=subject,
        TemplateBody=template,
        Parameters=_params(ParameterName=param_name, ParameterValue=param_value),
        NotificationARNs=[topic_arn],
        ClientRequestToken=token,
        Tags=tag,
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=subject))
    created = _poll_status(
        cfn, subject, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="subject create"
    )
    assert created == "CREATE_COMPLETE", f"stack {subject!r}: expected CREATE_COMPLETE, got {created!r}"

    physical_id = cfn.describe_stack_resource(StackName=subject, LogicalResourceId="Notified")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    assert physical_id == param_name, (
        f"template sanity: the parameter's physical id should be the name the check supplied "
        f"({param_name!r}), got {physical_id!r}"
    )

    # --- Terminal read AT THE CONSUMER ----------------------------------------------------------
    started = time.monotonic()
    notes = _drain_until(
        sqs,
        queue_url,
        want=lambda ns: _pick(ns, "Notified", "CREATE_COMPLETE") is not None
        and _pick(ns, subject, "CREATE_COMPLETE") is not None,
        timeout_s=DELIVERY_TIMEOUT_S,
        why="a CREATE_COMPLETE notification for the resource AND for the stack",
    )
    latency_s = time.monotonic() - started

    resource_note = _pick(notes, "Notified", "CREATE_COMPLETE")
    assert resource_note is not None, (
        f"no notification with LogicalResourceId='Notified' ResourceStatus='CREATE_COMPLETE' arrived "
        f"within {DELIVERY_TIMEOUT_S}s; saw "
        f"{sorted({(n.get('LogicalResourceId'), n.get('ResourceStatus')) for n in notes})!r}"
    )
    assert resource_note["StackName"] == subject, (
        f"notification StackName: expected {subject!r}, got {resource_note['StackName']!r}"
    )
    assert resource_note["StackId"] == stack_id, (
        f"notification StackId: expected {stack_id!r}, got {resource_note['StackId']!r}"
    )
    assert resource_note["ResourceType"] == "AWS::SSM::Parameter", (
        f"notification ResourceType: expected 'AWS::SSM::Parameter', got "
        f"{resource_note['ResourceType']!r}"
    )
    assert resource_note["PhysicalResourceId"] == physical_id, (
        f"notification PhysicalResourceId: expected the id DescribeStackResource reports "
        f"({physical_id!r}), got {resource_note['PhysicalResourceId']!r}"
    )
    assert resource_note["ClientRequestToken"] == token, (
        f"notification ClientRequestToken: expected {token!r}, got "
        f"{resource_note['ClientRequestToken']!r}"
    )

    # The join that no recorded transcript can carry: every delivered notification must correspond
    # to a REAL event in this stack's history, matched on the runtime-minted EventId. A target that
    # synthesises plausible notifications from the template fails here.
    real_event_ids = _event_ids(cfn, subject)
    delivered_ids = {n["EventId"] for n in notes if "EventId" in n}
    assert delivered_ids, f"no notification carried an EventId; parsed {notes[:2]!r}"
    assert delivered_ids <= real_event_ids, (
        f"every notified EventId must appear in DescribeStackEvents; "
        f"{sorted(delivered_ids - real_event_ids)!r} did not "
        f"({len(real_event_ids)} real events)"
    )

    stack_note = _pick(notes, subject, "CREATE_COMPLETE")
    assert stack_note is not None, (
        "no notification for the stack itself reached CREATE_COMPLETE; a target that notifies only "
        "resource events is missing half the stream"
    )

    # --- Negative leg: no NotificationARNs, no notifications -------------------------------------
    # The control is the delivery just proven on this exact wiring, measured at latency_s; the
    # barrier is structural — the second stack names no topic, so there is no path to withhold.
    quiet = ctx.unique_name("sim2real-cfn-quiet-s-")
    quiet_param = "/" + ctx.unique_name("sim2real-cfn-quiet-p-")
    cfn.create_stack(
        StackName=quiet,
        TemplateBody=template,
        Parameters=_params(ParameterName=quiet_param, ParameterValue=ctx.unique_name("quiet-")),
        Tags=tag,
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=quiet))
    quiet_status = _poll_status(
        cfn, quiet, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="control-group create"
    )
    assert quiet_status == "CREATE_COMPLETE", (
        f"control-group stack {quiet!r}: expected CREATE_COMPLETE, got {quiet_status!r}"
    )
    stray = _drain_for(sqs, queue_url, seconds=max(2.0 * latency_s, 20.0))
    leaked = [n for n in stray if n.get("StackName") == quiet]
    assert not leaked, (
        f"a stack created with no NotificationARNs must publish nothing to this topic; got "
        f"{len(leaked)} notifications naming {quiet!r} (first={leaked[:1]!r})"
    )


# ===== helpers =====


def _params(**kwargs: str) -> list[dict]:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in kwargs.items()]


def _poll_status(cfn, stack_name: str, terminal: set[str], *, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _parse_notification(body: str) -> dict[str, str]:
    """Parse CloudFormation's Key='value' notification body into a dict.

    Unparsed lines are dropped, and the caller hard-subscripts the keys it asserts on, so a body in
    a different shape fails loudly at the assertion rather than silently yielding {}.
    """
    out: dict[str, str] = {}
    for line in body.splitlines():
        match = _KV.match(line.strip())
        if match:
            out[match.group(1)] = match.group(2)
    return out


def _receive(sqs, queue_url: str, *, wait_s: int = 5) -> list[dict[str, str]]:
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s, VisibilityTimeout=30
    )
    out = []
    for msg in resp.get("Messages", []):
        out.append(_parse_notification(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain_until(sqs, queue_url: str, *, want, timeout_s: float, why: str) -> list[dict[str, str]]:
    deadline = time.monotonic() + timeout_s
    seen: list[dict[str, str]] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
        if want(seen):
            return seen
    raise AssertionError(
        f"queue never yielded [{why}] within {timeout_s}s; collected {len(seen)} notifications "
        f"{[(n.get('LogicalResourceId'), n.get('ResourceStatus')) for n in seen]!r}"
    )


def _drain_for(sqs, queue_url: str, *, seconds: float) -> list[dict[str, str]]:
    deadline = time.monotonic() + seconds
    seen: list[dict[str, str]] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
    return seen


def _pick(notes: list[dict[str, str]], logical_id: str, status: str) -> dict[str, str] | None:
    for note in notes:
        if note.get("LogicalResourceId") == logical_id and note.get("ResourceStatus") == status:
            return note
    return None


def _event_ids(cfn, stack_name: str) -> set[str]:
    ids: set[str] = set()
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            ids.add(event["EventId"])
    return ids


def _ignore_missing(fn) -> None:
    """Teardown helper: tolerate a resource already gone, and nothing else."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"NotFound", "InvalidParameter"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
