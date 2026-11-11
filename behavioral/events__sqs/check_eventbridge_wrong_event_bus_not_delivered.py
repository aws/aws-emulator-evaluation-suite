"""eventbridge-wrong-event-bus-not-delivered."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-wrong-event-bus-not-delivered"

GROUP = "event-propagation"

SERVICES = ["events", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A custom-bus rule never sees an event put on the default bus, which a default-bus rule
    receives; the same event put on the custom bus then reaches the custom-bus rule."""
    events = ctx.client("events")
    source = _xname(ctx, "src")

    bus = _xname(ctx, "bus")
    events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    default_q = _create_queue(ctx)
    bus_q = _create_queue(ctx)

    _put_rule_with_sqs_target(ctx, {"source": [source]}, default_q)
    _put_rule_with_sqs_target(ctx, {"source": [source]}, bus_q, bus=bus)

    def _entry(marker, event_bus=None):
        e = {
            "Source": source,
            "DetailType": "BusProbe",
            "Detail": json.dumps({"marker": marker}),
        }
        if event_bus:
            e["EventBusName"] = event_bus
        return e

    def _marker(want):
        return lambda b: (
            isinstance(b, dict) and b.get("detail", {}).get("marker") == want
        )

    # Control 1: the DEFAULT-bus event is accepted and matched by the default-bus rule.
    ctl, _ = _emit_until(
        ctx, [_entry("default-bus")], default_q["url"], _marker("default-bus")
    )
    assert len(ctl) >= 1, (
        "control: default-bus event never delivered to the default-bus rule"
    )

    # Negative: the custom-bus rule must not have seen any of it.
    leaked = _collect(ctx, bus_q["url"], window_s=30.0)
    assert leaked == [], (
        f"a rule on custom bus {bus!r} received {len(leaked)} default-bus event(s) -- bus "
        f"isolation is not enforced: {[_body(m) for m in leaked]}"
    )

    # Control 2: the same event published WITH EventBusName does reach the custom bus, proving the
    # custom-bus rule/target/queue-policy chain was functional while it stayed empty above.
    ctl2, _ = _emit_until(
        ctx, [_entry("custom-bus", bus)], bus_q["url"], _marker("custom-bus")
    )
    assert len(ctl2) >= 1, (
        "control: custom-bus event never delivered to its own bus rule"
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


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


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
    """Drain a queue over a bounded window with long-polling ReceiveMessage(MaxNumberOfMessages=10)
    and return EVERY message seen. Never raises and never swallows an assertion.

    This is the NEGATIVE observable. An empty return is only meaningful once a positive control
    has already been observed elsewhere in the check -- that is what proves enough wall-clock and
    enough propagation elapsed for a delivery to have happened if the emulator were going to make
    one. Used alone it would pass against an emulator that delivers nothing at all."""
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
    """PutEvents ALL of `entries` together, repeatedly, until a message whose parsed body satisfies
    `predicate` lands on `queue_url`. Returns (matched, others).

    Emitting every leg on every attempt is what makes the negative sound: a freshly created
    rule/target silently drops events until the path goes live and EventBridge never retries a
    dropped event, so the control has to be re-emitted -- and if the non-matching legs ride along
    on each attempt then, by the time the control arrives, every non-matching event has had at
    least as long to arrive as the control did. Non-delivery is therefore suppression, not lag."""
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
