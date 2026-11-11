"""events-delivery-and-failure-conflicting-input-and-input-path-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-conflicting-input-and-input-path-rejected"
GROUP = "error-propagation"
SERVICES = ["events", "sqs"]

_LIT_A = '{"v":"a"}'
_LIT_B = '{"v":"b"}'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Supplying both `Input` and `InputPath` on one target is refused with ValidationException,
    and the refused update has NO effect: the stored target and what it delivers are unchanged."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q = _queue(ctx, [rule_arn])

    first = events.put_targets(Rule=rule_name, Targets=[{"Id": "t", "Arn": q[1], "Input": _LIT_A}])
    assert first["FailedEntryCount"] == 0, f"PutTargets failed entries: {first.get('FailedEntries')!r}"

    def _deliveries(expect_bodies_until):
        bodies = []

        def _emit_and_read():
            out = events.put_events(Entries=[{
                "Source": source, "DetailType": "Conflict", "Detail": json.dumps({"k": 1}),
            }])
            assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
            bodies.extend(m["Body"] for m in _drain(sqs, q[0], seconds=2))
            return bodies

        return _poll_until(
            _emit_and_read, expect_bodies_until, timeout_s=150, interval_s=3,
            description="the target delivering",
        )

    before = _deliveries(lambda b: len(b) >= 1)
    assert set(before) == {_LIT_A}, f"target must deliver literal A before the refused update, got {before!r}"
    stored_before = events.list_targets_by_rule(Rule=rule_name)["Targets"]

    code = message = None
    try:
        events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": "t", "Arn": q[1], "Input": _LIT_B, "InputPath": "$.detail"}],
        )
    except ClientError as err:
        code, message = err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    assert code == "ValidationException", (
        f"Input together with InputPath must be refused with ValidationException, got {code!r}"
    )
    assert message == "Only one of Input, InputPath, or InputTransformer must be provided for target t.", (
        f"unexpected ValidationException message {message!r}"
    )

    stored_after = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert stored_after == stored_before, (
        f"a refused PutTargets must leave the stored target untouched: {stored_before!r} -> {stored_after!r}"
    )
    # Effect absent at the destination: after the refusal, deliveries remain literal A.
    _drain(sqs, q[0], seconds=2)
    after = _deliveries(lambda b: len(b) >= 2)
    assert set(after) == {_LIT_A}, (
        f"after the refused update the target must still deliver literal A only, got {after!r}"
    )

    # Positive control: remove the one conflicting field and the update lands.
    ok = events.put_targets(Rule=rule_name, Targets=[{"Id": "t", "Arn": q[1], "Input": _LIT_B}])
    assert ok["FailedEntryCount"] == 0, f"valid update failed: {ok.get('FailedEntries')!r}"
    switched = _deliveries(lambda b: _LIT_B in b)
    assert set(switched) <= {_LIT_A, _LIT_B}, f"unexpected bodies after the valid update: {switched!r}"


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
