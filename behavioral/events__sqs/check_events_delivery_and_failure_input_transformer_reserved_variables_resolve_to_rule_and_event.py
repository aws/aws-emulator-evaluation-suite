"""events-delivery-and-failure-input-transformer-reserved-variables-resolve-to-rule-and-event."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-input-transformer-reserved-variables-resolve-to-rule-and-event"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_TEMPLATE = (
    '{"rule":<aws.events.rule-name>,"arn":<aws.events.rule-arn>,'
    '"ing":<aws.events.event.ingestion-time>,"ev":<aws.events.event>,'
    '"evj":<aws.events.event.json>}'
)


def _parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """The reserved InputTransformer variables resolve to THIS rule and THIS event at delivery: rule
    name and ARN, the full event, the event without detail, and the bus's ingestion time."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_tx = _queue(ctx, [rule_arn])
    q_raw = _queue(ctx, [rule_arn])
    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "tx", "Arn": q_tx[1], "InputTransformer": {"InputTemplate": _TEMPLATE}},
            {"Id": "raw", "Arn": q_raw[1]},
        ],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"

    past = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0)
    tx_by_id, raw_by_id = {}, {}

    def _emit_and_collect():
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "Reserved", "Time": past,
            "Detail": json.dumps({"nonce": uuid.uuid4().hex}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        for msg in _drain(sqs, q_tx[0], seconds=2):
            body = json.loads(msg["Body"])
            tx_by_id[body["evj"]["id"]] = body
        for msg in _drain(sqs, q_raw[0], seconds=2):
            body = json.loads(msg["Body"])
            raw_by_id[body["id"]] = body
        return sorted(set(tx_by_id) & set(raw_by_id))

    joined = _poll_until(
        _emit_and_collect, lambda ids: len(ids) >= 1, timeout_s=180, interval_s=3,
        description="one event delivered to both the transformed and the control target",
    )
    event_id = joined[0]
    tx, raw = tx_by_id[event_id], raw_by_id[event_id]

    assert tx["rule"] == rule_name, f"<aws.events.rule-name> rendered {tx['rule']!r}, rule is {rule_name!r}"
    assert tx["arn"] == rule_arn, f"<aws.events.rule-arn> rendered {tx['arn']!r}, PutRule returned {rule_arn!r}"
    assert tx["evj"] == raw, (
        f"<aws.events.event.json> must equal the full envelope delivered to the control target; "
        f"got {tx['evj']!r} vs control {raw!r}"
    )
    assert "detail" in tx["evj"], f"<aws.events.event.json> must include detail, got {tx['evj']!r}"
    assert isinstance(tx["ev"], dict) and tx["ev"].get("id") == event_id, (
        f"<aws.events.event> must be the same event (id {event_id!r}), got {tx['ev']!r}"
    )
    assert "detail" not in tx["ev"], (
        f"<aws.events.event> is documented WITHOUT the detail field, got {tx['ev']!r}"
    )

    assert _parse_ts(raw["time"]) == past, (
        f"the envelope must carry the explicit past Time {past.isoformat()!r}, got {raw['time']!r}"
    )
    ingested = _parse_ts(tx["ing"])
    assert ingested - past > timedelta(hours=1), (
        f"<aws.events.event.ingestion-time> {tx['ing']!r} must be the bus receive time, not the "
        f"event's own time {raw['time']!r}"
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
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
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
