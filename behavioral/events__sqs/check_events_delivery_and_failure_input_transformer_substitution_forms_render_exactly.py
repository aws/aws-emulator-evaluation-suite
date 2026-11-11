"""events-delivery-and-failure-input-transformer-substitution-forms-render-exactly."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-input-transformer-substitution-forms-render-exactly"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_ORDER = {"id": "o-17", "qty": 3, "lines": [{"sku": "a"}]}
_DETAIL = {"order": _ORDER, "who": "alice", "flag": True, "quo": 'say "hi"'}
_PATHS = {
    "id": "$.detail.order.id",
    "qty": "$.detail.order.qty",
    "order": "$.detail.order",
    "who": "$.detail.who",
    "flag": "$.detail.flag",
    "quo": "$.detail.quo",
    "miss": "$.detail.nope",
}
_JSON_TEMPLATE = (
    '{"quoted":"order <id> by <who>","bare":<id>,"qty":<qty>,"qtyq":"<qty>",'
    '"obj":<order>,"flag":<flag>,"quo":<quo>,"quoq":"<quo>","missq":"x<miss>y","miss":<miss>}'
)
# The plain-text form: the template is a JSON STRING literal, quotes included. (A bare, unquoted
# sentence is refused by PutTargets.)
_TEXT_TEMPLATE = '"order <id> by <who> qty <qty> miss[<miss>]"'

_EXPECTED_JSON = {
    "quoted": "order o-17 by alice",
    "bare": "o-17",
    "qty": 3,
    "qtyq": "3",
    "obj": _ORDER,
    "flag": True,
    "quo": 'say "hi"',
    "quoq": 'say "hi"',
    "missq": "xy",
    "miss": "",
}
_EXPECTED_TEXT = '"order o-17 by alice qty 3 miss[]"'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every InputTransformer substitution form (string, number, object, boolean, escaped quotes,
    in-string splice, unresolvable path, plain-text template) renders exactly what EventBridge
    renders, compared against an unshaped control copy of the same event."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_json = _queue(ctx, [rule_arn])
    q_text = _queue(ctx, [rule_arn])
    q_raw = _queue(ctx, [rule_arn])

    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "json", "Arn": q_json[1],
             "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _JSON_TEMPLATE}},
            {"Id": "text", "Arn": q_text[1],
             "InputTransformer": {"InputPathsMap": dict(_PATHS), "InputTemplate": _TEXT_TEMPLATE}},
            {"Id": "raw", "Arn": q_raw[1]},
        ],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"

    got = {"json": [], "text": [], "raw": []}
    queues = {"json": q_json[0], "text": q_text[0], "raw": q_raw[0]}

    def _emit_and_collect():
        out = events.put_events(
            Entries=[{"Source": source, "DetailType": "Transform", "Detail": json.dumps(_DETAIL)}]
        )
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        for key, url in queues.items():
            got[key].extend(_drain(sqs, url, seconds=2))
        return {k: len(v) for k, v in got.items()}

    # A brand-new rule drops events until its targets go live, so re-emit the SAME event until
    # every target has received at least one copy. Every copy must render identically.
    _poll_until(
        _emit_and_collect,
        lambda counts: all(n >= 1 for n in counts.values()),
        timeout_s=180,
        interval_s=3,
        description="every target (json, text, raw) receiving the event",
    )
    for key, url in queues.items():
        got[key].extend(_drain(sqs, url, seconds=4))

    raw = json.loads(got["raw"][0]["Body"])
    assert raw.get("detail") == _DETAIL, (
        f"control target must receive the untouched envelope with the full detail, got {raw!r}"
    )

    for msg in got["json"]:
        body = json.loads(msg["Body"])
        assert body == _EXPECTED_JSON, (
            f"JSON template rendered {body!r}; expected {_EXPECTED_JSON!r}"
        )
        assert "detail" not in body and "source" not in body, (
            f"the transformed body must not carry the raw envelope, got {body!r}"
        )

    for msg in got["text"]:
        assert msg["Body"] == _EXPECTED_TEXT, (
            f"plain-text template rendered {msg['Body']!r}; expected {_EXPECTED_TEXT!r}"
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
