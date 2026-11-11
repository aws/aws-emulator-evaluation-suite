"""events-delivery-and-failure-deleted-queue-target-dead-letters-no-resource-while-sibling-delivers."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-deleted-queue-target-dead-letters-no-resource-while-sibling-delivers"
GROUP = "error-propagation"
SERVICES = ["events", "sqs"]

_RETRY = {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """When a rule's SQS target queue is deleted out from under it, EventBridge dead-letters each
    matched event for THAT target with ERROR_CODE=NO_RESOURCE, while the healthy sibling target on
    the same rule keeps receiving the very same events."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_victim = _queue(ctx, [rule_arn])
    q_ok = _queue(ctx, [rule_arn])
    q_dlq = _queue(ctx, [rule_arn])

    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "victim", "Arn": q_victim[1], "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY},
            {"Id": "ok", "Arn": q_ok[1], "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY},
        ],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"

    def _emit():
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "Victim", "Detail": json.dumps({"nonce": uuid.uuid4().hex}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        return out["Entries"][0]["EventId"]

    # Phase 1: both targets live and delivering.
    seen = {"victim": [], "ok": []}

    def _emit_and_collect_both():
        _emit()
        seen["victim"].extend(_drain(sqs, q_victim[0], seconds=2))
        seen["ok"].extend(_drain(sqs, q_ok[0], seconds=2))
        return {k: len(v) for k, v in seen.items()}

    _poll_until(_emit_and_collect_both, lambda c: c["victim"] >= 1 and c["ok"] >= 1,
                timeout_s=180, interval_s=3, description="both targets receiving before the deletion")
    early_dlq = _drain(sqs, q_dlq[0], seconds=2)
    assert early_dlq == [], (
        f"nothing may dead-letter while both targets exist, got {[m.get('MessageAttributes') for m in early_dlq]!r}"
    )

    # Break exactly one thing.
    sqs.delete_queue(QueueUrl=q_victim[0])

    ok_by_id, dlq_msgs, emitted = {}, [], set()

    def _emit_and_collect_failure():
        emitted.add(_emit())
        for msg in _drain(sqs, q_ok[0], seconds=2):
            ok_by_id[json.loads(msg["Body"])["id"]] = msg["Body"]
        dlq_msgs.extend(_drain(sqs, q_dlq[0], seconds=2))
        victim_ids = {
            json.loads(m["Body"])["id"] for m in dlq_msgs
            if m.get("MessageAttributes", {}).get("TARGET_ARN", {}).get("StringValue") == q_victim[1]
        }
        return sorted(victim_ids & set(ok_by_id) & emitted)

    # SQS deletion propagates over time; keep emitting until an event emitted AFTER the deletion
    # is dead-lettered for the victim and delivered to the healthy sibling.
    joined = _poll_until(_emit_and_collect_failure, lambda ids: len(ids) >= 1, timeout_s=200, interval_s=3,
                         description="a post-deletion event dead-lettered for the victim and delivered to the sibling")
    event_id = joined[0]
    dlq_msgs.extend(_drain(sqs, q_dlq[0], seconds=2))

    for msg in dlq_msgs:
        attrs = {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}
        assert attrs.get("TARGET_ARN") == q_victim[1], (
            f"only the deleted target may dead-letter; got TARGET_ARN {attrs.get('TARGET_ARN')!r} "
            f"(healthy is {q_ok[1]!r})"
        )
    victim_msg = next(m for m in dlq_msgs if json.loads(m["Body"])["id"] == event_id)
    attrs = {k: v.get("StringValue") for k, v in victim_msg["MessageAttributes"].items()}
    assert attrs.get("ERROR_CODE") == "NO_RESOURCE", f"expected ERROR_CODE=NO_RESOURCE, got {attrs!r}"
    assert "AWS.SimpleQueueService.NonExistentQueue" in (attrs.get("ERROR_MESSAGE") or ""), (
        f"ERROR_MESSAGE must name the missing queue error, got {attrs.get('ERROR_MESSAGE')!r}"
    )
    assert attrs.get("RULE_ARN") == rule_arn, f"expected RULE_ARN={rule_arn!r}, got {attrs!r}"
    assert json.loads(victim_msg["Body"]) == json.loads(ok_by_id[event_id]), (
        f"the dead-lettered body must be the same envelope the sibling received; "
        f"DLQ {victim_msg['Body']!r} vs sibling {ok_by_id[event_id]!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _rule(ctx, pattern):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-edf-")
    arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern))["RuleArn"]

    def _delete():
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name).get("Targets", [])]
        if ids:
            events.remove_targets(Rule=name, Ids=ids)
        events.delete_rule(Name=name)

    ctx.on_cleanup(_delete)
    return name, arn


def _queue(ctx, rule_arns):
    """A queue whose policy lets EventBridge deliver to it, scoped to exactly these rules."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-edf-q-"), tags={"sim2real": "events-delivery-and-failure"}
    )["QueueUrl"]

    def _delete():
        try:
            sqs.delete_queue(QueueUrl=url)
        except sqs.exceptions.QueueDoesNotExist:
            pass  # the victim queue is deleted by the check itself

    ctx.on_cleanup(_delete)
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": list(rule_arns)}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain(sqs, url, *, seconds):
    """Receive-and-delete for `seconds`. An empty list is a real observation, not a default."""
    out = []
    deadline = time.monotonic() + seconds
    while True:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
            MessageAttributeNames=["All"], AttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if time.monotonic() >= deadline:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
