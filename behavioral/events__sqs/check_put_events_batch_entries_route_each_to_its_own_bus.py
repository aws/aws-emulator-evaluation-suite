"""put-events-batch-entries-route-each-to-its-own-bus."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-events-batch-entries-route-each-to-its-own-bus"

GROUP = "put-events"

SERVICES = ["events", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBusName is per entry: one PutEvents batch lands each entry on the bus it names.

    Same-pattern rules on the default and a custom bus each receive only their own entry (no
    EventBusName vs the custom bus ARN), never the other's.
    """
    events = ctx.client("events")
    source = _xname(ctx, "src")
    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    pattern = {"source": [source]}
    default_q = _create_queue(ctx)
    custom_q = _create_queue(ctx)
    _put_rule_with_sqs_target(ctx, pattern, default_q)
    _put_rule_with_sqs_target(ctx, pattern, custom_q, bus=bus)

    entries = [
        {"Source": source, "DetailType": "Sim2realPerEntryBus", "Detail": json.dumps({"leg": "default"})},
        {
            "Source": source,
            "DetailType": "Sim2realPerEntryBus",
            "Detail": json.dumps({"leg": "custom"}),
            "EventBusName": bus_arn,
        },
    ]

    def legs(msgs: list[dict]) -> list[Any]:
        return [_body(m).get("detail", {}).get("leg") if isinstance(_body(m), dict) else _body(m) for m in msgs]

    on_default: list[Any] = []
    on_custom: list[Any] = []
    for _ in range(12):
        resp = events.put_events(Entries=entries)
        assert resp["FailedEntryCount"] == 0, f"PutEvents refused an entry: {resp['Entries']!r}"
        on_default.extend(legs(_collect(ctx, default_q["url"], window_s=6.0)))
        on_custom.extend(legs(_collect(ctx, custom_q["url"], window_s=6.0)))
        if "default" in on_default and "custom" in on_custom:
            break
    assert "default" in on_default, f"the default-bus entry never reached the default rule's queue: {on_default!r}"
    assert "custom" in on_custom, f"the custom-bus entry never reached the custom rule's queue: {on_custom!r}"

    on_default.extend(legs(_collect(ctx, default_q["url"], window_s=8.0)))
    on_custom.extend(legs(_collect(ctx, custom_q["url"], window_s=8.0)))
    assert set(on_default) == {"default"}, (
        f"the default bus's queue received legs {sorted(set(map(str, on_default)))!r}, expected only 'default'"
    )
    assert set(on_custom) == {"custom"}, (
        f"the custom bus's queue received legs {sorted(set(map(str, on_custom)))!r}, expected only 'custom'"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10, keep=False):
    """Drain a queue over a bounded window and return every message seen; never raises.
    An empty result means "not delivered" only after a positive control has arrived."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            if not keep:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.
    Returns (matched, others) -- every non-matching message seen along the way is returned too so
    the caller can assert on leakage instead of silently discarding it."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _allow_service_send(queue_arn: str, service: str, source_arn: str) -> dict:
    """A queue policy granting one AWS service SendMessage on this queue, scoped by SourceArn."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowServiceSend",
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _put_rule_with_sqs_target(
    ctx,
    pattern: dict,
    queue: dict,
    *,
    bus: str | None = None,
    target: dict | None = None,
) -> str:
    """Create an EventBridge rule for `pattern`, grant the rule SendMessage on `queue`, and attach
    the queue as target t1. Registers remove_targets + delete_rule teardown (reverse order of
    creation). Returns the rule name."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    kwargs: dict[str, Any] = {"Name": name, "EventPattern": json.dumps(pattern)}
    if bus:
        kwargs["EventBusName"] = bus
    rule_arn = events.put_rule(**kwargs)["RuleArn"]
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(
            Name=name, **({"EventBusName": bus} if bus else {}), Force=True
        )
    )
    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn),
    )
    tgt: dict[str, Any] = {"Id": "t1", "Arn": queue["arn"]}
    if target:
        tgt.update(target)
    events.put_targets(
        Rule=name, Targets=[tgt], **({"EventBusName": bus} if bus else {})
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=name, Ids=["t1"], **({"EventBusName": bus} if bus else {})
        )
    )
    return name


def _emit_until(ctx, entries, queue_url, predicate, *, attempts=10, poll_s=8.0):
    """PutEvents all of `entries` together until one satisfying `predicate` lands on `queue_url`;
    a new rule drops events until live, and every leg rides each attempt so absence is not lag.
    Returns (matched, others)."""
    events = ctx.client("events")
    others: list[dict[str, Any]] = []
    for _ in range(attempts):
        events.put_events(Entries=list(entries))
        got, extra = _wait_for(ctx, queue_url, predicate, timeout_s=poll_s)
        others.extend(extra)
        if got:
            return got, others
    raise AssertionError(
        f"control event never delivered to {queue_url} after {attempts} PutEvents attempts "
        f"(non-matching messages seen meanwhile: {len(others)}) -- the positive leg of this "
        "negative-delivery check could not be established, so the negative is unprovable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
