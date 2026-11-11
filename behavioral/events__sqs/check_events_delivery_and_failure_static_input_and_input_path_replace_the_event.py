"""events-delivery-and-failure-static-input-and-input-path-replace-the-event."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-static-input-and-input-path-replace-the-event"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

# Deliberately NOT in canonical json.dumps form (spaces after ':' and ','): real EventBridge
# delivers the literal byte-for-byte, so a re-serialising emulator is caught.
_LITERAL = '{"fixed": "literal", "n": 1}'
_ORDER = {"id": "o-17", "qty": 3, "lines": [{"sku": "a"}]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A static `Input` replaces the event with a literal, delivered verbatim; `InputPath` replaces
    it with the selected subtree -- an object as the object, a string as a JSON string."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_lit = _queue(ctx, [rule_arn])
    q_obj = _queue(ctx, [rule_arn])
    q_str = _queue(ctx, [rule_arn])
    q_raw = _queue(ctx, [rule_arn])

    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "lit", "Arn": q_lit[1], "Input": _LITERAL},
            {"Id": "obj", "Arn": q_obj[1], "InputPath": "$.detail.order"},
            {"Id": "str", "Arn": q_str[1], "InputPath": "$.detail.who"},
            {"Id": "raw", "Arn": q_raw[1]},
        ],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"

    queues = {"lit": q_lit[0], "obj": q_obj[0], "str": q_str[0], "raw": q_raw[0]}
    got = {k: [] for k in queues}
    nonces = set()

    def _emit_and_collect():
        nonce = uuid.uuid4().hex
        nonces.add(nonce)
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "Replace",
            "Detail": json.dumps({"order": _ORDER, "who": "alice", "nonce": nonce}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        for key, url in queues.items():
            got[key].extend(m["Body"] for m in _drain(sqs, url, seconds=2))
        return {k: len(v) for k, v in got.items()}

    _poll_until(
        _emit_and_collect, lambda counts: all(n >= 1 for n in counts.values()),
        timeout_s=180, interval_s=3, description="every target (lit, obj, str, raw) receiving the event",
    )

    for body in got["raw"]:
        env = json.loads(body)
        assert env.get("source") == source and env["detail"]["nonce"] in nonces, (
            f"control target must receive the full envelope of an emitted event, got {env!r}"
        )
    for body in got["lit"]:
        assert body == _LITERAL, f"static Input must be delivered verbatim; expected {_LITERAL!r}, got {body!r}"
    for body in got["obj"]:
        assert json.loads(body) == _ORDER, (
            f"InputPath $.detail.order must deliver exactly that object, got {body!r}"
        )
    for body in got["str"]:
        assert body == '"alice"', f"InputPath $.detail.who must deliver the JSON string '\"alice\"', got {body!r}"


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
