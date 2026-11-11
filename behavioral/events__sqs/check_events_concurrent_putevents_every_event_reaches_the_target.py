"""events-concurrent-putevents-every-event-reaches-the-target."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "events-concurrent-putevents-every-event-reaches-the-target"

GROUP = "event-propagation"

SERVICES = ["events", "sqs"]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Forty events put by eight concurrent callers all reach the rule's SQS target: the delivered
    nonces equal the published ones, with duplicates counted since delivery is at-least-once."""
    events = ctx.client("events")
    source = _xname(ctx, "src").replace("-", ".")
    queue = _create_queue(ctx)
    rule = _put_rule_with_sqs_target(ctx, {"source": [source]}, queue)

    # A freshly created rule/target silently drops events until the path goes live, and EventBridge
    # never retries a dropped event -- so the path has to be proven live BEFORE the load, or a
    # shortfall afterwards is indistinguishable from warm-up. One delivered control is not enough
    # (a burst issued right after the first control arrives can still lose events), so require
    # THREE consecutive single-event round trips before publishing anything that counts.
    _settle_delivery_path(ctx, source, queue["url"], consecutive=3)
    _collect(ctx, queue["url"], window_s=5.0, max_total=100)

    published: set[str] = set()
    batches: list[list[str]] = []
    for _ in range(8):
        batch = [_xname(ctx, "n") for _ in range(5)]
        batches.append(batch)
        published.update(batch)
    assert len(published) == 40, f"nonce minting collided: {len(published)} unique of 40: {sorted(published)!r}"

    def _publish(batch: list[str]) -> dict[str, Any]:
        client = ctx.client("events")
        return client.put_events(
            Entries=[
                {"Source": source, "DetailType": "Load", "Detail": json.dumps({"nonce": n})}
                for n in batch
            ]
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(_publish, batches))

    event_ids: list[str] = []
    for i, resp in enumerate(responses):
        assert resp.get("FailedEntryCount") == 0, (
            f"caller {i} had partial failures: FailedEntryCount="
            f"{resp.get('FailedEntryCount')!r} Entries={resp.get('Entries')!r}"
        )
        entries = resp.get("Entries", [])
        assert len(entries) == 5, f"caller {i} expected 5 result entries, got {entries!r}"
        for e in entries:
            assert e.get("EventId"), f"caller {i} entry without an EventId: {e!r}"
            event_ids.append(e["EventId"])
    dupe_ids = sorted({i for i in event_ids if event_ids.count(i) > 1})
    assert dupe_ids == [], (
        f"PutEvents minted a duplicate EventId across concurrent callers: {dupe_ids!r} "
        f"(all 40 were {event_ids!r})"
    )

    delivered: list[str] = []
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline and len(set(delivered)) < 40:
        for msg in _collect(ctx, queue["url"], window_s=10.0, max_total=100):
            body = _body(msg)
            if isinstance(body, dict) and isinstance(body.get("detail"), dict):
                nonce = body["detail"].get("nonce")
                if nonce in published:
                    delivered.append(nonce)

    missing = sorted(published - set(delivered))
    assert missing == [], (
        f"rule {rule} lost {len(missing)} of 40 concurrently published events; missing nonces "
        f"{missing!r} (delivered {len(set(delivered))} distinct of {len(delivered)} messages)"
    )
    # At-least-once is the documented contract, so a redelivery is reported, never failed.
    duplicates = len(delivered) - len(set(delivered))
    print(f"[observed] 40/40 nonces delivered; at-least-once redeliveries observed: {duplicates}")

    trailing = _collect(ctx, queue["url"], window_s=10.0, max_total=100)
    unknown = [
        _body(m)
        for m in trailing
        if not (
            isinstance(_body(m), dict)
            and isinstance(_body(m).get("detail"), dict)
            and _body(m)["detail"].get("nonce") in published
        )
    ]
    assert unknown == [], (
        f"queue {queue['name']} received {len(unknown)} message(s) carrying no published nonce, so "
        f"the set comparison above was measured against contaminated traffic: {unknown!r}"
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
    """Drain a queue over a bounded window with long-polling ReceiveMessage(MaxNumberOfMessages=10)
    and return EVERY message seen. Never raises and never swallows an assertion."""
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
    """Poll a queue until a message whose parsed body satisfies predicate() arrives."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s), max_total=100):
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
            Rule=name, Ids=["t1"], Force=True, **({"EventBusName": bus} if bus else {})
        )
    )
    return name


def _settle_delivery_path(ctx, source: str, queue_url: str, *, consecutive: int = 3) -> None:
    """Emit single control events until `consecutive` of them round-trip back to back.

    A rule and its target become effective progressively on real EventBridge, and a dropped event is
    never retried, so one arrival proves only that SOME path is live. Requiring several consecutive
    round trips is the barrier that makes a later shortfall attributable to loss rather than to
    warm-up. This polls an observable condition (the control's own arrival) rather than sleeping."""
    events = ctx.client("events")
    streak = 0
    for _ in range(30):
        nonce = _xname(ctx, "ctl")
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Control",
                    "Detail": json.dumps({"nonce": nonce}),
                }
            ]
        )
        got, _ = _wait_for(
            ctx,
            queue_url,
            lambda b, n=nonce: isinstance(b, dict) and b.get("detail", {}).get("nonce") == n,
            timeout_s=15.0,
        )
        streak = streak + 1 if got else 0
        if streak >= consecutive:
            return
    raise AssertionError(
        f"the rule -> {queue_url} delivery path never round-tripped {consecutive} consecutive "
        f"control events, so nothing measured after this point would be attributable to loss "
        f"rather than to warm-up (longest streak reached: {streak})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
