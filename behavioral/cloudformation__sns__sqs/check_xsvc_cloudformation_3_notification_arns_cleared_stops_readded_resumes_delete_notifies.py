"""xsvc-cloudformation-3-notification-arns-cleared-stops-readded-resumes-delete-notifies."""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudformation-3-notification-arns-cleared-stops-readded-resumes-delete-notifies"
GROUP = "deploy-eventing"
SERVICES = ["cloudformation", "sns", "sqs"]

STACK_TIMEOUT_S = 240.0
DELIVERY_TIMEOUT_S = 150.0
_KV = re.compile(r"^([A-Za-z]+)='(.*)'$")

# One SSM parameter whose value is a stack parameter, so each UpdateStack below is a REAL update
# that emits stack and resource events (an update with nothing to do is refused outright).
_TEMPLATE = json.dumps(
    {
        "Parameters": {"V": {"Type": "String"}},
        "Resources": {
            "P": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": {"Ref": "V"}}}
        },
    }
)


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """UpdateStack with NotificationARNs=[] clears a stack's topic and omission keeps it: the cleared
    stack's next update publishes nothing while a witness stack's simultaneous update delivers,
    re-adding the topic resumes delivery, and DeleteStack's DELETE_COMPLETE reaches the queue."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    stack_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    topic_arn, queue_url = _wire_topic_queue(ctx, sns, sqs)

    subject = ctx.unique_name("sim2real-xsvc-cfn3-notif-s-")
    witness = ctx.unique_name("sim2real-xsvc-cfn3-notif-w-")
    tok = {k: ctx.unique_name(f"sim2realcfn3{k}-") for k in ("sc", "wc", "u1", "u2", "w2", "u3", "del")}

    # --- 1. Both stacks created notifying the same topic -----------------------------------------
    subject_id = cfn.create_stack(
        StackName=subject, TemplateBody=_TEMPLATE, Parameters=_v("a"),
        NotificationARNs=[topic_arn], ClientRequestToken=tok["sc"], Tags=stack_tags,
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=subject_id))
    witness_id = cfn.create_stack(
        StackName=witness, TemplateBody=_TEMPLATE, Parameters=_v("a"),
        NotificationARNs=[topic_arn], ClientRequestToken=tok["wc"], Tags=stack_tags,
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=witness_id))
    for sid, why in ((subject_id, "subject create"), (witness_id, "witness create")):
        status = _poll_status(cfn, sid, why=why)
        assert status == "CREATE_COMPLETE", f"[{why}] expected CREATE_COMPLETE, got {status!r}"

    notes: list[dict[str, str]] = []
    started = time.monotonic()
    _drain_until(
        sqs, queue_url, notes,
        want=lambda ns: _stack_note(ns, subject, "CREATE_COMPLETE", tok["sc"]) is not None,
        why="the subject's own CREATE_COMPLETE notification (positive control on this queue)",
    )
    latency_s = time.monotonic() - started
    created_note = _stack_note(notes, subject, "CREATE_COMPLETE", tok["sc"])
    assert created_note["StackId"] == subject_id, (
        f"CREATE_COMPLETE notification StackId: expected {subject_id!r}, got {created_note['StackId']!r}"
    )

    # --- 2. Clear: NotificationARNs=[] is a mutation of stack state -----------------------------
    cfn.update_stack(
        StackName=subject_id, TemplateBody=_TEMPLATE, Parameters=_v("b"),
        NotificationARNs=[], ClientRequestToken=tok["u1"],
    )
    status = _poll_status(cfn, subject_id, why="clearing update")
    assert status == "UPDATE_COMPLETE", f"clearing update: expected UPDATE_COMPLETE, got {status!r}"
    cleared = cfn.describe_stacks(StackName=subject_id)["Stacks"][0].get("NotificationARNs")
    assert cleared == [], f"after UpdateStack(NotificationARNs=[]) DescribeStacks reports {cleared!r}, expected []"

    # --- 3. Quiet leg: the cleared subject and the still-notifying witness, updated together -----
    # Neither call names NotificationARNs, so omission must PRESERVE each stack's current list:
    # [] for the subject, [topic] for the witness. The witness's delivery is the barrier.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [
            pool.submit(cfn.update_stack, StackName=subject_id, TemplateBody=_TEMPLATE,
                        Parameters=_v("c"), ClientRequestToken=tok["u2"]),
            pool.submit(cfn.update_stack, StackName=witness_id, TemplateBody=_TEMPLATE,
                        Parameters=_v("c"), ClientRequestToken=tok["w2"]),
        ]
        for fut in futs:
            fut.result()
    for sid, why in ((subject_id, "subject quiet update"), (witness_id, "witness update")):
        status = _poll_status(cfn, sid, why=why)
        assert status == "UPDATE_COMPLETE", f"[{why}] expected UPDATE_COMPLETE, got {status!r}"
    still_cleared = cfn.describe_stacks(StackName=subject_id)["Stacks"][0].get("NotificationARNs")
    assert still_cleared == [], (
        f"an update that omits NotificationARNs must keep the cleared list; DescribeStacks reports "
        f"{still_cleared!r}"
    )
    witness_arns = cfn.describe_stacks(StackName=witness_id)["Stacks"][0].get("NotificationARNs")
    assert witness_arns == [topic_arn], (
        f"an update that omits NotificationARNs must keep the witness's list; got {witness_arns!r}"
    )

    _drain_until(
        sqs, queue_url, notes,
        want=lambda ns: _stack_note(ns, witness, "UPDATE_COMPLETE", tok["w2"]) is not None,
        why="the witness's UPDATE_COMPLETE for the concurrent update (the differential barrier)",
    )
    notes.extend(_drain_for(sqs, queue_url, seconds=max(2.0 * latency_s, 20.0)))
    witness_events = [n for n in notes if n.get("ClientRequestToken") == tok["w2"]]
    assert len(witness_events) >= 2, (
        f"the witness update should deliver its stack AND resource events; got "
        f"{[(n.get('LogicalResourceId'), n.get('ResourceStatus')) for n in witness_events]!r}"
    )
    leaked = [n for n in notes if n.get("ClientRequestToken") == tok["u2"]]
    assert not leaked, (
        f"the subject's NotificationARNs were cleared, yet its next update published "
        f"{len(leaked)} notifications: "
        f"{[(n.get('LogicalResourceId'), n.get('ResourceStatus')) for n in leaked]!r}"
    )

    # --- 4. Re-add: delivery resumes on the very same queue --------------------------------------
    cfn.update_stack(
        StackName=subject_id, TemplateBody=_TEMPLATE, Parameters=_v("d"),
        NotificationARNs=[topic_arn], ClientRequestToken=tok["u3"],
    )
    status = _poll_status(cfn, subject_id, why="re-adding update")
    assert status == "UPDATE_COMPLETE", f"re-adding update: expected UPDATE_COMPLETE, got {status!r}"
    readded = cfn.describe_stacks(StackName=subject_id)["Stacks"][0].get("NotificationARNs")
    assert readded == [topic_arn], f"after re-adding, DescribeStacks reports {readded!r}"
    # SNS -> SQS does not preserve order, so wait for BOTH the stack's and the resource's
    # UPDATE_COMPLETE rather than treating the stack's as the last one to arrive.
    _drain_until(
        sqs, queue_url, notes,
        want=lambda ns: _stack_note(ns, subject, "UPDATE_COMPLETE", tok["u3"]) is not None
        and _stack_note(ns, "P", "UPDATE_COMPLETE", tok["u3"]) is not None,
        why="the subject's stack AND resource UPDATE_COMPLETE after the topic was re-added",
    )
    resumed_resource = [
        n for n in notes
        if n.get("ClientRequestToken") == tok["u3"] and n.get("LogicalResourceId") == "P"
        and n.get("ResourceStatus") == "UPDATE_COMPLETE"
    ]
    assert resumed_resource, (
        f"re-added notifications must include the resource's UPDATE_COMPLETE; got "
        f"{[(n.get('LogicalResourceId'), n.get('ResourceStatus')) for n in notes if n.get('ClientRequestToken') == tok['u3']]!r}"
    )

    # --- 5. DeleteStack notifies DELETE_COMPLETE ---------------------------------------------------
    cfn.delete_stack(StackName=subject_id, ClientRequestToken=tok["del"])
    status = _poll_status(cfn, subject_id, terminal={"DELETE_COMPLETE", "DELETE_FAILED"}, why="delete")
    assert status == "DELETE_COMPLETE", f"subject delete: expected DELETE_COMPLETE, got {status!r}"
    _drain_until(
        sqs, queue_url, notes,
        want=lambda ns: _stack_note(ns, subject, "DELETE_COMPLETE", tok["del"]) is not None,
        why="the subject's DELETE_COMPLETE notification",
    )
    deleted_note = _stack_note(notes, subject, "DELETE_COMPLETE", tok["del"])
    assert deleted_note["StackId"] == subject_id, (
        f"DELETE_COMPLETE notification StackId: expected {subject_id!r}, got {deleted_note['StackId']!r}"
    )
    assert deleted_note["ResourceType"] == "AWS::CloudFormation::Stack", (
        f"DELETE_COMPLETE notification ResourceType: got {deleted_note['ResourceType']!r}"
    )


def _v(value: str) -> list[dict]:
    return [{"ParameterKey": "V", "ParameterValue": value}]


def _wire_topic_queue(ctx, sns, sqs):
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-cfn3-t-"), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-cfn3-q-"), tags={"sim2real-check": CHECK}
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
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))
    return topic_arn, queue_url


def _poll_status(cfn, stack_id: str, *, why: str, terminal: set[str] | None = None) -> str:
    """Poll until the stack leaves *_IN_PROGRESS (or reaches `terminal`); RAISES on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if (terminal and last in terminal) or (not terminal and not last.endswith("_IN_PROGRESS")):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {STACK_TIMEOUT_S}s [{why}]")


def _parse_notification(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in body.splitlines():
        match = _KV.match(line.strip())
        if match:
            out[match.group(1)] = match.group(2)
    return out


def _receive(sqs, queue_url: str) -> list[dict[str, str]]:
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=30
    )
    out = []
    for msg in resp.get("Messages", []):
        out.append(_parse_notification(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain_until(sqs, queue_url: str, seen: list, *, want, why: str) -> None:
    deadline = time.monotonic() + DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
        if want(seen):
            return
    raise AssertionError(
        f"queue never yielded [{why}] within {DELIVERY_TIMEOUT_S}s; collected "
        f"{[(n.get('LogicalResourceId'), n.get('ResourceStatus'), n.get('ClientRequestToken')) for n in seen]!r}"
    )


def _drain_for(sqs, queue_url: str, *, seconds: float) -> list[dict[str, str]]:
    deadline = time.monotonic() + seconds
    seen: list[dict[str, str]] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
    return seen


def _stack_note(notes, stack_name: str, status: str, token: str):
    for note in notes:
        if (
            note.get("LogicalResourceId") == stack_name
            and note.get("ResourceStatus") == status
            and note.get("ClientRequestToken") == token
        ):
            return note
    return None


def _ignore_missing(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"NotFound", "InvalidParameter"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
