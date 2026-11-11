"""obs-cloudformation-3-notification-arns-stream-update-rollback-delete-and-stop-when-cleared."""
# On AWS:
#   * Resources emit several consecutive `*_IN_PROGRESS` events per transition (e.g. a second
#     UPDATE_IN_PROGRESS reading "Eventual consistency check initiated"). The asserted sequences are the
#     STATUS transitions with consecutive repeats collapsed; the per-EventId bijection below separately
#     pins the exact number of notifications to the exact number of events.
#   * A stack-level update always passes through UPDATE_COMPLETE_CLEANUP_IN_PROGRESS (and a rollback
#     through UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS), so those are part of the exact stack
#     sequence.
#   * The failure is an invalid property VALUE on the existing resource: `Value: ''` for
#     AWS::SSM::Parameter passes template validation and is rejected by the resource handler
#     (PutParameter), giving UPDATE_FAILED on the resource with the handler text, then a rollback. A
#     failing NEW second resource cannot produce this sequence — it reports CREATE_FAILED, never
#     UPDATE_FAILED — so the failure has to land on a resource that already exists.
#   * SNS -> SQS delivery is unordered, so the order is read from DescribeStackEvents and the
#     notifications are matched to it per EventId.
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cloudformation-3-notification-arns-stream-update-rollback-delete-and-stop-when-cleared"
GROUP = "eventing"
SERVICES = ["cloudformation", "sns", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
STACK_TIMEOUT_S = 240.0
DELIVERY_TIMEOUT_S = 180.0
_KV = re.compile(r"^([A-Za-z]+)='(.*)'$")

#: Fields of a notification that must equal the same-EventId event's field in DescribeStackEvents.
_JOINED_FIELDS = (
    "StackId",
    "StackName",
    "LogicalResourceId",
    "PhysicalResourceId",
    "ResourceType",
    "ResourceStatus",
    "ResourceStatusReason",
)

HANDLER_FAILURE_PREFIX = "Resource handler returned message: \"Error occurred during operation 'PutParameter'.\""
HANDLER_FAILURE_CODE = "HandlerErrorCode: GeneralServiceException"
ROLLBACK_REASON = "The following resource(s) failed to update: [Notified]. "


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Update, rollback and delete events reach the queue one-for-one with DescribeStackEvents;
    NotificationARNs=[] silences the stream; omitting NotificationARNs preserves the current value."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    template = (DEPLOYMENTS / "notified-stack.yaml").read_text()

    # --- Consumer wiring, created in-check ------------------------------------------------------
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-cfnobs-t-"), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-cfnobs-q-"), tags={"sim2real-check": CHECK}
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
        # Raw delivery: the queue body is CloudFormation's own Key='value' text, not an SNS envelope.
        Attributes={"RawMessageDelivery": "true"},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))
    raw = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get("RawMessageDelivery")
    assert raw == "true", f"subscription RawMessageDelivery: expected 'true', got {raw!r}"

    # Every notification ever received, keyed by EventId (SNS is at-least-once: a duplicate collapses).
    notes: dict[str, dict[str, str]] = {}
    seen_events: set[str] = set()

    # --- Create, with the topic -----------------------------------------------------------------
    stack_name = ctx.unique_name("sim2real-xsvc-cfnobs-s-")
    param_name = "/" + ctx.unique_name("sim2real-xsvc-cfnobs-p-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=_params(param_name, ctx.unique_name("v0-")),
        NotificationARNs=[topic_arn],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    status = _poll_status(cfn, stack_id, why="create")
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {status!r}"
    create_events = _new_events(cfn, stack_id, seen_events)
    _await_delivery(sqs, queue_url, notes, create_events, why="create")

    # --- U1: a parameter change, NotificationARNs OMITTED ----------------------------------------
    value_u1 = ctx.unique_name("v1-")
    cfn.update_stack(StackName=stack_id, UsePreviousTemplate=True, Parameters=_params(param_name, value_u1))
    status = _poll_status(cfn, stack_id, why="update U1")
    assert status == "UPDATE_COMPLETE", f"U1: expected UPDATE_COMPLETE, got {status!r}"
    u1 = _new_events(cfn, stack_id, seen_events)
    started = time.monotonic()
    _await_delivery(sqs, queue_url, notes, u1, why="U1 (clean update, NotificationARNs omitted)")
    latency_s = time.monotonic() - started
    _assert_joined(notes, u1, "U1")
    _assert_sequence(u1, "Notified", ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], "U1")
    _assert_sequence(
        u1, stack_name, ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_COMPLETE"], "U1"
    )

    # --- U2: an invalid property value the handler rejects -> rollback ---------------------------
    cfn.update_stack(StackName=stack_id, UsePreviousTemplate=True, Parameters=_params(param_name, ""))
    status = _poll_status(cfn, stack_id, why="update U2 (expected rollback)")
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"U2: expected UPDATE_ROLLBACK_COMPLETE, got {status!r}"
    u2 = _new_events(cfn, stack_id, seen_events)
    _await_delivery(sqs, queue_url, notes, u2, why="U2 (failed update + rollback)")
    _assert_joined(notes, u2, "U2")
    _assert_sequence(
        u2, "Notified", ["UPDATE_IN_PROGRESS", "UPDATE_FAILED", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], "U2"
    )
    _assert_sequence(
        u2,
        stack_name,
        [
            "UPDATE_IN_PROGRESS",
            "UPDATE_ROLLBACK_IN_PROGRESS",
            "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_ROLLBACK_COMPLETE",
        ],
        "U2",
    )
    failed = [e for e in u2 if e["LogicalResourceId"] == "Notified" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(failed) == 1, f"U2: expected exactly one UPDATE_FAILED event for Notified, got {len(failed)}"
    failed_note = notes[failed[0]["EventId"]]
    reason = failed_note["ResourceStatusReason"]
    assert reason.startswith(HANDLER_FAILURE_PREFIX) and HANDLER_FAILURE_CODE in reason, (
        f"U2: the UPDATE_FAILED notification must carry the handler's error text "
        f"({HANDLER_FAILURE_PREFIX!r} ... {HANDLER_FAILURE_CODE!r}); got {reason!r}"
    )
    rb = [e for e in u2 if e["LogicalResourceId"] == stack_name and e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"]
    assert len(rb) == 1, f"U2: expected one stack UPDATE_ROLLBACK_IN_PROGRESS event, got {len(rb)}"
    rb_reason = notes[rb[0]["EventId"]]["ResourceStatusReason"]
    assert rb_reason == ROLLBACK_REASON, (
        f"U2: stack rollback notification reason: expected {ROLLBACK_REASON!r}, got {rb_reason!r}"
    )
    kept = _param_value(cfn, stack_id)
    assert kept == value_u1, f"U2 rolled back, so ParameterValue must be U1's {value_u1!r}; got {kept!r}"

    # --- U3: explicit NotificationARNs=[] clears the topic ---------------------------------------
    cfn.update_stack(
        StackName=stack_id,
        UsePreviousTemplate=True,
        Parameters=_params(param_name, ctx.unique_name("v3-")),
        NotificationARNs=[],
    )
    status = _poll_status(cfn, stack_id, why="update U3 (clear NotificationARNs)")
    assert status == "UPDATE_COMPLETE", f"U3: expected UPDATE_COMPLETE, got {status!r}"
    arns = cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("NotificationARNs")
    assert arns == [], f"U3: NotificationARNs=[] must clear the stack's topics; DescribeStacks shows {arns!r}"
    # U3's own events straddle the switch, so none of them is asserted either way; marking them seen
    # keeps U4's window to U4's events only.
    _new_events(cfn, stack_id, seen_events)

    # --- U4: a further update with NotificationARNs omitted -> must publish NOTHING -------------
    cfn.update_stack(
        StackName=stack_id, UsePreviousTemplate=True, Parameters=_params(param_name, ctx.unique_name("v4-"))
    )
    status = _poll_status(cfn, stack_id, why="update U4 (topics cleared)")
    assert status == "UPDATE_COMPLETE", f"U4: expected UPDATE_COMPLETE, got {status!r}"
    u4 = _new_events(cfn, stack_id, seen_events)
    u4_ids = {e["EventId"] for e in u4}
    # The update really happened (so there WAS something to publish): its own events say so.
    _assert_sequence(u4, "Notified", ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], "U4")
    # Quiet window sized off the delivery latency measured on this very wiring in U1. It is not the
    # barrier on its own: U5/U6/delete below must deliver on the same queue while U4's ids stay absent.
    _drain_for(sqs, queue_url, notes, seconds=max(3.0 * latency_s, 15.0))
    leaked = sorted(u4_ids & notes.keys())
    assert not leaked, (
        f"U4: after NotificationARNs=[] no stack event may be published, yet {len(leaked)} of U4's "
        f"{len(u4_ids)} events arrived: {[(notes[i]['LogicalResourceId'], notes[i]['ResourceStatus']) for i in leaked]!r}"
    )

    # --- U5: re-arm with the topic (the repair leg: the queue was reachable all along) -----------
    cfn.update_stack(
        StackName=stack_id,
        UsePreviousTemplate=True,
        Parameters=_params(param_name, ctx.unique_name("v5-")),
        NotificationARNs=[topic_arn],
    )
    status = _poll_status(cfn, stack_id, why="update U5 (re-arm)")
    assert status == "UPDATE_COMPLETE", f"U5: expected UPDATE_COMPLETE, got {status!r}"
    _new_events(cfn, stack_id, seen_events)

    # --- U6: NotificationARNs OMITTED again -> must keep delivering (omitted != empty) -----------
    cfn.update_stack(
        StackName=stack_id, UsePreviousTemplate=True, Parameters=_params(param_name, ctx.unique_name("v6-"))
    )
    status = _poll_status(cfn, stack_id, why="update U6 (omitted NotificationARNs)")
    assert status == "UPDATE_COMPLETE", f"U6: expected UPDATE_COMPLETE, got {status!r}"
    arns = cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("NotificationARNs")
    assert arns == [topic_arn], f"U6: omitting NotificationARNs must keep [{topic_arn!r}]; got {arns!r}"
    u6 = _new_events(cfn, stack_id, seen_events)
    _await_delivery(sqs, queue_url, notes, u6, why="U6 (update with NotificationARNs omitted after re-arm)")
    _assert_joined(notes, u6, "U6")
    _assert_sequence(u6, "Notified", ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], "U6")

    # --- Delete --------------------------------------------------------------------------------
    cfn.delete_stack(StackName=stack_id)
    status = _poll_status(cfn, stack_id, why="delete")
    assert status == "DELETE_COMPLETE", f"delete: expected DELETE_COMPLETE, got {status!r}"
    dl = _new_events(cfn, stack_id, seen_events)
    _await_delivery(sqs, queue_url, notes, dl, why="delete")
    _assert_joined(notes, dl, "delete")
    _assert_sequence(dl, "Notified", ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"], "delete")
    _assert_sequence(dl, stack_name, ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"], "delete")

    # --- Whole-stream invariants -----------------------------------------------------------------
    # Every notification ever received names a real event of THIS stack (no synthesised notes), and
    # U4's events never arrived even though three later operations delivered on the same queue.
    unknown = sorted(set(notes) - seen_events)
    assert not unknown, (
        f"{len(unknown)} notifications carry an EventId absent from DescribeStackEvents: "
        f"{[(notes[i].get('LogicalResourceId'), notes[i].get('ResourceStatus')) for i in unknown]!r}"
    )
    late = sorted(u4_ids & notes.keys())
    assert not late, f"U4's events arrived late, after the stream was re-armed: {late!r}"


# ===== helpers =====


def _params(name: str, value: str) -> list[dict]:
    return [
        {"ParameterKey": "ParameterName", "ParameterValue": name},
        {"ParameterKey": "ParameterValue", "ParameterValue": value},
    ]


def _param_value(cfn, stack_id: str) -> str:
    for p in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Parameters"]:
        if p["ParameterKey"] == "ParameterValue":
            return p["ParameterValue"]
    raise AssertionError(f"stack {stack_id!r} reports no ParameterValue parameter")


def _poll_status(cfn, stack_id: str, *, why: str) -> str:
    """Poll until the stack leaves *_IN_PROGRESS; RAISES on timeout rather than returning."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not last.endswith("_IN_PROGRESS"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {STACK_TIMEOUT_S}s [{why}]")


def _new_events(cfn, stack_id: str, seen: set[str]) -> list[dict]:
    """This stack's events not yet in `seen`, in CHRONOLOGICAL order; marks them seen."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    fresh = [e for e in reversed(events) if e["EventId"] not in seen]
    seen.update(e["EventId"] for e in fresh)
    return fresh


def _parse_notification(body: str) -> dict[str, str]:
    """Parse CloudFormation's Key='value' notification body (unparsed lines are dropped)."""
    out: dict[str, str] = {}
    for line in body.splitlines():
        match = _KV.match(line.strip())
        if match:
            out[match.group(1)] = match.group(2)
    return out


def _receive(sqs, queue_url: str, notes: dict[str, dict[str, str]]) -> None:
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=30
    )
    for msg in resp.get("Messages", []):
        note = _parse_notification(msg["Body"])
        assert "EventId" in note, f"queued message is not a CloudFormation notification: {msg['Body'][:300]!r}"
        notes[note["EventId"]] = note
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _await_delivery(sqs, queue_url: str, notes: dict, events: list[dict], *, why: str) -> None:
    """Drain until EVERY event of the operation has a same-EventId notification."""
    assert events, f"[{why}] DescribeStackEvents reported no new events for the operation"
    want = {e["EventId"] for e in events}
    deadline = time.monotonic() + DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline:
        if want <= notes.keys():
            return
        _receive(sqs, queue_url, notes)
    if want <= notes.keys():
        return
    missing = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events if e["EventId"] not in notes]
    raise AssertionError(
        f"[{why}] {len(missing)} of {len(want)} stack events were never notified within "
        f"{DELIVERY_TIMEOUT_S}s: {missing!r}"
    )


def _drain_for(sqs, queue_url: str, notes: dict, *, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        _receive(sqs, queue_url, notes)


def _assert_joined(notes: dict, events: list[dict], label: str) -> None:
    """Each event's notification agrees with DescribeStackEvents field by field."""
    for e in events:
        note = notes[e["EventId"]]
        for field in _JOINED_FIELDS:
            want = e.get(field) or ""
            got = note.get(field)
            assert got == want, (
                f"{label}: notification {e['EventId']!r} ({e['LogicalResourceId']} {e['ResourceStatus']}) "
                f"field {field}: DescribeStackEvents says {want!r}, notification says {got!r}"
            )


def _assert_sequence(events: list[dict], logical_id: str, expected: list[str], label: str) -> None:
    """Exact status transitions for one logical id, consecutive repeats collapsed."""
    seq: list[str] = []
    for e in events:
        if e["LogicalResourceId"] == logical_id and (not seq or seq[-1] != e["ResourceStatus"]):
            seq.append(e["ResourceStatus"])
    assert seq == expected, f"{label}: {logical_id!r} status sequence: expected {expected!r}, got {seq!r}"


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
