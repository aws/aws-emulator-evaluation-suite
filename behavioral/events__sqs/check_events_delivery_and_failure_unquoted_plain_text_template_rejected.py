"""events-delivery-and-failure-unquoted-plain-text-template-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-unquoted-plain-text-template-rejected"
GROUP = "error-propagation"
SERVICES = ["events", "sqs"]

_PATHS = {"id": "$.detail.id", "who": "$.detail.who"}
_BARE = "order <id> by <who>"
_QUOTED = '"order <id> by <who>"'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutTargets refuses a bare-sentence InputTemplate with ValidationException and its exact
    message and stores no target; the same sentence as a JSON string literal is accepted and
    delivers the rendered text."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_text = _queue(ctx, [rule_arn])
    q_raw = _queue(ctx, [rule_arn])

    ctl = events.put_targets(Rule=rule_name, Targets=[{"Id": "raw", "Arn": q_raw[1]}])
    assert ctl["FailedEntryCount"] == 0, f"control PutTargets failed: {ctl.get('FailedEntries')!r}"

    code = message = None
    try:
        events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": "text", "Arn": q_text[1],
                      "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _BARE}}],
        )
    except ClientError as err:
        code, message = err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    assert code == "ValidationException", (
        f"a bare-sentence InputTemplate must be refused with ValidationException, got {code!r}"
    )
    # The service parses the template with every placeholder read as null.
    parsed = _BARE.replace("<id>", "null").replace("<who>", "null")
    expected = f'Invalid InputTemplate for target text : [Source: (String)"{parsed}"; line: 1, column: 1].'
    assert message == expected, f"unexpected ValidationException message {message!r}"
    ids = sorted(t["Id"] for t in events.list_targets_by_rule(Rule=rule_name)["Targets"])
    assert ids == ["raw"], f"the refused target must not be stored; rule has targets {ids!r}"

    raw_got, text_got = [], []

    def _emit_and_collect():
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "Text", "Detail": json.dumps({"id": "o-17", "who": "alice"}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        raw_got.extend(_drain(sqs, q_raw[0], seconds=2))
        text_got.extend(_drain(sqs, q_text[0], seconds=1))
        return len(raw_got)

    _poll_until(_emit_and_collect, lambda n: n >= 2, timeout_s=150, interval_s=3,
                description="the control target receiving two events")
    text_got.extend(_drain(sqs, q_text[0], seconds=5))
    assert text_got == [], (
        f"the refused target's queue must receive nothing, got {[m['Body'] for m in text_got]!r}"
    )

    ok = events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "text", "Arn": q_text[1],
                  "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _QUOTED}}],
    )
    assert ok["FailedEntryCount"] == 0, f"quoted template must be accepted: {ok.get('FailedEntries')!r}"

    delivered = []

    def _emit_and_read_text():
        _emit_and_collect()
        delivered.extend(m["Body"] for m in _drain(sqs, q_text[0], seconds=1))
        delivered.extend(m["Body"] for m in text_got)
        text_got.clear()
        return delivered

    _poll_until(_emit_and_read_text, lambda b: len(b) >= 1, timeout_s=150, interval_s=3,
                description="the quoted plain-text target delivering")
    for body in delivered:
        assert body == '"order o-17 by alice"', f"quoted plain-text template delivered {body!r}"


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
