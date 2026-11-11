"""events-delivery-and-failure-object-in-quoted-template-string-dead-letters-as-invalid-json."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-object-in-quoted-template-string-dead-letters-as-invalid-json"
GROUP = "error-propagation"
SERVICES = ["events", "sqs"]

_ORDER = {"id": "o-17", "qty": 3}
_PATHS = {"order": "$.detail.order", "n": "$.detail.n"}
_BAD_TEMPLATE = '{"objq":"<order>","n":<n>}'
_GOOD_TEMPLATE = '{"obj":<order>,"n":<n>}'
_RETRY = {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}


def _bad_render(n):
    # What EventBridge actually hands the target: the object's JSON spliced verbatim between the
    # template's quotes, with no escaping -- so the result is not JSON.
    return '{"objq":"' + json.dumps(_ORDER, separators=(",", ":")) + '","n":' + str(n) + "}"


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An InputTransformer that splices an OBJECT into a quoted JSON string renders invalid JSON;
    EventBridge refuses to deliver it, dead-letters it with ERROR_CODE=INVALID_JSON, and a sibling
    target on the same rule still receives the same event."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_bad = _queue(ctx, [rule_arn])
    q_good = _queue(ctx, [rule_arn])
    q_dlq = _queue(ctx, [rule_arn])

    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "bad", "Arn": q_bad[1], "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY,
             "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _BAD_TEMPLATE}},
            {"Id": "good", "Arn": q_good[1], "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY,
             "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _GOOD_TEMPLATE}},
        ],
    )
    assert resp["FailedEntryCount"] == 0, (
        f"PutTargets must ACCEPT the quoted-object template (the failure is at delivery), "
        f"got {resp.get('FailedEntries')!r}"
    )

    good_ns, dlq_msgs, bad_msgs = set(), [], []
    counter = {"n": 0}

    def _emit(detail_n):
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "Splice",
            "Detail": json.dumps({"order": _ORDER, "n": detail_n}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"

    def _emit_and_collect():
        counter["n"] += 1
        _emit(counter["n"])
        for msg in _drain(sqs, q_good[0], seconds=2):
            body = json.loads(msg["Body"])
            assert body["obj"] == _ORDER, f"healthy sibling rendered {body!r}"
            good_ns.add(body["n"])
        dlq_msgs.extend(_drain(sqs, q_dlq[0], seconds=2))
        bad_msgs.extend(_drain(sqs, q_bad[0], seconds=1))
        dlq_ns = {int(m["Body"].rsplit('"n":', 1)[1].rstrip("}")) for m in dlq_msgs}
        return sorted(good_ns & dlq_ns)

    common = _poll_until(
        _emit_and_collect, lambda ns: len(ns) >= 1, timeout_s=180, interval_s=3,
        description="one event reaching the healthy sibling AND the DLQ",
    )
    n = common[0]
    # Keep reading well past the barrier: any delivery to the broken queue would have had time to
    # arrive, because the sibling's copy of the SAME event already did.
    bad_msgs.extend(_drain(sqs, q_bad[0], seconds=10))
    dlq_msgs.extend(_drain(sqs, q_dlq[0], seconds=2))

    assert bad_msgs == [], (
        f"a target whose rendered input is invalid JSON must receive nothing, got "
        f"{[m['Body'] for m in bad_msgs]!r}"
    )
    assert dlq_msgs, "the DLQ must hold the undeliverable event"
    for msg in dlq_msgs:
        attrs = {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}
        assert attrs.get("TARGET_ARN") == q_bad[1], (
            f"only the broken target may dead-letter; DLQ message names {attrs.get('TARGET_ARN')!r}, "
            f"broken target is {q_bad[1]!r}, healthy is {q_good[1]!r}"
        )
        assert attrs.get("ERROR_CODE") == "INVALID_JSON", f"expected ERROR_CODE=INVALID_JSON, got {attrs!r}"
        assert attrs.get("ERROR_MESSAGE") == "Invalid input for target.", (
            f"expected ERROR_MESSAGE='Invalid input for target.', got {attrs.get('ERROR_MESSAGE')!r}"
        )
        assert attrs.get("RULE_ARN") == rule_arn, f"expected RULE_ARN={rule_arn!r}, got {attrs!r}"
    dlq_bodies = {m["Body"] for m in dlq_msgs}
    assert _bad_render(n) in dlq_bodies, (
        f"the DLQ body must be the rendered (malformed) payload {_bad_render(n)!r}, got {sorted(dlq_bodies)!r}"
    )
    for body in dlq_bodies:
        assert '"source"' not in body and '"detail"' not in body, (
            f"the DLQ must carry the rendered payload, not the source event envelope: {body!r}"
        )

    # Repair exactly the one broken thing: unquote the placeholder. The same queue must now receive.
    fixed = events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "bad", "Arn": q_bad[1], "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY,
                  "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _GOOD_TEMPLATE}}],
    )
    assert fixed["FailedEntryCount"] == 0, f"repair PutTargets failed: {fixed.get('FailedEntries')!r}"
    repaired = []

    def _emit_and_read_bad():
        counter["n"] += 1
        _emit(counter["n"])
        repaired.extend(json.loads(m["Body"]) for m in _drain(sqs, q_bad[0], seconds=3))
        return repaired

    _poll_until(
        _emit_and_read_bad, lambda bodies: len(bodies) >= 1, timeout_s=120, interval_s=3,
        description="the repaired target receiving the unquoted object",
    )
    assert repaired[0]["obj"] == _ORDER, f"repaired target rendered {repaired[0]!r}"


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
