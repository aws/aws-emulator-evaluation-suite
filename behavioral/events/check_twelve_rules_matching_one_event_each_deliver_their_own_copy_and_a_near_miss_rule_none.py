"""twelve-rules-matching-one-event-each-deliver-their-own-copy-and-a-near-miss-rule-none."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "twelve-rules-matching-one-event-each-deliver-their-own-copy-and-a-near-miss-rule-none"
GROUP = "rule-fanout"
SERVICES = ["events"]

_LIVENESS_TIMEOUT_S = 180.0
_DELIVERY_TIMEOUT_S = 90.0

# Twelve different patterns that every one match the measured event below, written in the
# pattern-language forms customers mix on one bus. The measured event is
# source=<src>, detail-type "order.placed", detail {"m": <marker>, "qty": 5, "tier": "gold",
# "tags": ["a", "b"], "ip": "10.0.3.7"}.
_MATCHING = {
    "by-source": {},
    "by-detail-type": {"detail-type": ["order.placed"]},
    "by-prefix": {"detail-type": [{"prefix": "order."}]},
    "by-suffix": {"detail-type": [{"suffix": ".placed"}]},
    "by-numeric": {"detail": {"qty": [{"numeric": [">", 1, "<=", 5]}]}},
    "by-anything-but": {"detail": {"tier": [{"anything-but": ["bronze"]}]}},
    "by-exists": {"detail": {"tier": [{"exists": True}]}},
    "by-array-element": {"detail": {"tags": ["b"]}},
    "by-cidr": {"detail": {"ip": [{"cidr": "10.0.0.0/16"}]}},
    "by-ignore-case": {"detail": {"tier": [{"equals-ignore-case": "GOLD"}]}},
    "by-wildcard": {"detail-type": [{"wildcard": "order.*"}]},
    "by-or": {"$or": [{"detail": {"qty": [99]}}, {"detail": {"tier": ["gold"]}}]},
}
# A near-miss: the same source and detail-type, a tier the event does not carry. Its own
# control event (tier "silver") proves the rule is live and routes to the same queue.
_NEAR_MISS = {"detail-type": ["order.placed"], "detail": {"tier": ["silver"]}}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Twelve rules in different pattern forms targeting one queue each deliver their own copy of
    one event, all carrying its EventId, while a live near-miss rule on that queue delivers none.
    """
    events = ctx.client("events")
    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.fanout.")
    queue_url, queue_arn = _create_queue(ctx)

    rules: dict[str, str] = {}
    for label, extra in {**_MATCHING, "near-miss": _NEAR_MISS}.items():
        pattern = {"source": [source], **extra}
        name = _create_rule(ctx, events, bus, pattern)
        rules[label] = name
        # <aws.events.rule-name> stamps each copy with its rule, so one queue tells them apart.
        put = events.put_targets(Rule=name, EventBusName=bus, Targets=[{
            "Id": "q", "Arn": queue_arn,
            "InputTransformer": {
                "InputPathsMap": {"id": "$.id", "m": "$.detail.m"},
                "InputTemplate": '{"rule": <aws.events.rule-name>, "id": <id>, "m": <m>}',
            },
        }])
        assert put["FailedEntryCount"] == 0, f"PutTargets on {label!r} failed: {put['FailedEntries']!r}"
    matching = {rules[label] for label in _MATCHING}
    near_miss = rules["near-miss"]

    def _entry(marker: str, tier: str) -> dict:
        return {"EventBusName": bus, "Source": source, "DetailType": "order.placed",
                "Detail": json.dumps({"m": marker, "qty": 5, "tier": tier, "tags": ["a", "b"],
                                      "ip": "10.0.3.7"})}

    # Liveness: a just-created rule can drop events until its routing is live, so re-publish a
    # gold control event until all twelve rules have delivered it, and a silver one until the
    # near-miss rule has delivered it.
    _publish_until(ctx, events, queue_url, lambda m: _entry(m, "gold"), matching, "gold control")
    _publish_until(ctx, events, queue_url, lambda m: _entry(m, "silver"), {near_miss}, "silver control")

    marker = ctx.unique_name("measured-")
    resp = events.put_events(Entries=[_entry(marker, "gold")])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the measured event: {resp['Entries']!r}"
    event_id = resp["Entries"][0]["EventId"]

    copies = _drain(ctx, queue_url, marker, until=lambda got: {c["rule"] for c in got} >= matching,
                    timeout_s=_DELIVERY_TIMEOUT_S)
    by_rule = {c["rule"] for c in copies}
    assert by_rule == matching, (
        f"the measured event must reach the queue once per matching rule: {len(matching)} rules "
        f"matched, copies came from {len(by_rule & matching)} of them; missing "
        f"{sorted(label for label, n in rules.items() if n in matching - by_rule)!r}, near-miss "
        f"rule delivered: {near_miss in by_rule!r}"
    )
    ids = {c["id"] for c in copies}
    assert ids == {event_id}, (
        f"every copy must carry the one EventId PutEvents returned; {len(ids)} distinct id(s), "
        f"match: {event_id in ids!r}"
    )

    # The near-miss rule is live (it delivered its silver control) and shares the queue, so a
    # copy of the gold event from it would have arrived alongside the twelve. Drain a little
    # longer to catch a late one.
    late = _drain(ctx, queue_url, marker, until=lambda got: False, timeout_s=15.0, allow_timeout=True)
    assert near_miss not in {c["rule"] for c in copies + late}, (
        "the rule whose pattern requires tier 'silver' delivered the tier-'gold' event"
    )


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> str:
    name = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED")

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        }],
    })})
    return url, arn


def _receive(ctx, queue_url: str) -> list[dict]:
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain(ctx, queue_url: str, marker: str, *, until, timeout_s: float,
           allow_timeout: bool = False) -> list[dict]:
    """Copies of the event carrying ``marker``, received until ``until(copies)`` holds."""
    got: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got.extend(c for c in _receive(ctx, queue_url) if c.get("m") == marker)
        if until(got):
            return got
    if allow_timeout:
        return got
    raise AssertionError(
        f"copies of the measured event still incomplete after {timeout_s}s: {len(got)} received"
    )


def _publish_until(ctx, events, queue_url: str, make_entry, want_rules: set, what: str) -> None:
    """Publish fresh control events until every rule in ``want_rules`` has delivered one."""
    seen: set = set()
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    while time.monotonic() < deadline:
        marker = ctx.unique_name("live-")
        events.put_events(Entries=[make_entry(marker)])
        window = time.monotonic() + 15.0
        while time.monotonic() < window:
            seen |= {c["rule"] for c in _receive(ctx, queue_url) if c.get("m", "").startswith("live-")}
            if seen >= want_rules:
                return
    raise AssertionError(
        f"the {what} event never reached the queue through {len(want_rules - seen)} of "
        f"{len(want_rules)} rule(s) within {_LIVENESS_TIMEOUT_S}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
