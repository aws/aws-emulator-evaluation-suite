"""update-event-bus-policy-enforced-on-put-events."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-event-bus-policy-enforced-on-put-events"
GROUP = "server-side"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:events-default-bus-policy")
def run(ctx) -> None:
    """An explicit Deny in the default bus's resource policy (set with PutPermission) makes PutEvents
    fail as a whole with AccessDeniedException and the event is never delivered to the rule's queue;
    restoring the original policy restores delivery."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    source = ctx.unique_name("sim2real.policytest.")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source]}),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventsToSendMessage",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )

    target_id = "sim2real-target"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    # Positive control #1: with no restrictive policy yet, PutEvents succeeds and delivers.
    _put_and_confirm_delivery(ctx, events, sqs, queue_url, source, "before-policy")

    # PutPermission(Policy=...) is the only way to express a Deny, and it replaces the whole bus
    # policy; snapshot the account-singleton policy and restore exactly that on cleanup.
    original_policy = events.describe_event_bus(Name="default").get("Policy")
    statements = [
        s
        for s in (json.loads(original_policy)["Statement"] if original_policy else [])
        if s.get("Sid") != "DenyOwnAccountPutEventsForThisTest"
    ]

    # An explicit resource-policy Deny overrides the allowing identity policy. The events:source
    # condition scopes it to this check's unique source so other default-bus traffic is unaffected.
    deny_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": statements
            + [
                {
                    "Sid": "DenyOwnAccountPutEventsForThisTest",
                    "Effect": "Deny",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "events:PutEvents",
                    "Resource": bus_arn,
                    "Condition": {"StringEquals": {"events:source": source}},
                }
            ],
        }
    )
    events.put_permission(Policy=deny_policy)
    ctx.on_cleanup(lambda: _restore_bus_policy_quiet(events, original_policy))

    described = events.describe_event_bus(Name="default")
    assert "DenyOwnAccountPutEventsForThisTest" in (described.get("Policy") or "")

    blocked_detail = json.dumps({"stage": "after-policy", "nonce": ctx.unique_name("n-")})
    error_code = _put_until_denied(events, source, blocked_detail, timeout_s=60.0)
    assert error_code == "AccessDeniedException", error_code

    # A PutEvents made before the Deny fully propagated can legitimately deliver; discard those.
    _drain_messages(sqs, queue_url, timeout_s=5)

    # With enforcement steady, a fresh event must be denied and never reach the queue.
    steady_nonce = ctx.unique_name("n-")
    steady_detail = json.dumps({"stage": "after-policy-steady", "nonce": steady_nonce})
    steady_error_code = _put_until_denied(events, source, steady_detail, timeout_s=15.0)
    assert steady_error_code == "AccessDeniedException", steady_error_code

    leaked = _drain_messages(sqs, queue_url, timeout_s=8)
    matching = [m for m in leaked if steady_nonce in m]
    assert matching == [], f"message delivered despite explicit-deny bus policy: {matching}"


    # Positive control #2: with the Deny removed, delivery resumes.
    _restore_bus_policy(events, original_policy)
    _put_and_confirm_delivery(ctx, events, sqs, queue_url, source, "after-removal")


def _put_until_denied(ctx_events: Any, source: str, detail_json: str, timeout_s: float) -> str:
    """Poll PutEvents until the whole call raises AccessDeniedException.

    A bus resource-policy Deny rejects the entire request, not individual entries.
    """
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    last_resp: dict | None = None
    while time.monotonic() < deadline:
        try:
            last_resp = ctx_events.put_events(
                Entries=[
                    {
                        "Source": source,
                        "DetailType": "sim2real-test",
                        "Detail": detail_json,
                    }
                ]
            )
            last_exc = None
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code")
            if code == "AccessDeniedException":
                return code
        time.sleep(3.0)
    raise AssertionError(
        f"deny policy was never enforced within {timeout_s}s: "
        f"last_exc={last_exc!r} last_resp={last_resp!r}"
    )



def _put_and_confirm_delivery(ctx: Any, events: Any, sqs: Any, queue_url: str, source: str, stage: str) -> None:
    nonce = ctx.unique_name("n-")
    detail_json = json.dumps({"stage": stage, "nonce": nonce})

    # Policy add/remove can take a few seconds to propagate; retry past a transient
    # AccessDeniedException (raised as a ClientError, or reported as a resp failure)
    # instead of asserting on the very first attempt.
    put_deadline = time.monotonic() + 30.0
    resp: dict = {}
    while time.monotonic() < put_deadline:
        try:
            resp = events.put_events(
                Entries=[
                    {
                        "Source": source,
                        "DetailType": "sim2real-test",
                        "Detail": detail_json,
                    }
                ]
            )
        except ClientError:
            time.sleep(3.0)
            continue
        if resp["FailedEntryCount"] == 0:
            break
        time.sleep(3.0)
    assert resp.get("FailedEntryCount") == 0, resp.get("Entries")


    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        for msg in received:
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("detail", {}).get("nonce") == nonce:
                return
        time.sleep(0.5)
    raise AssertionError(f"stage={stage!r} event was never delivered to the queue")


def _drain_messages(sqs: Any, queue_url: str, timeout_s: float) -> list:
    out = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        for msg in received:
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if not received:
            time.sleep(0.5)
    return out


def _restore_bus_policy(events: Any, original_policy: str | None) -> None:
    """Put the default bus's policy back exactly as found, rather than wiping it --
    the bus's policy is an account-global singleton this check does not own."""
    if original_policy:
        events.put_permission(Policy=original_policy)
    else:
        events.remove_permission(RemoveAllPermissions=True)


def _restore_bus_policy_quiet(events: Any, original_policy: str | None) -> None:
    try:
        _restore_bus_policy(events, original_policy)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

