"""put-events-time-resources-and-event-id-carried-into-the-delivered-envelope."""

from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-events-time-resources-and-event-id-carried-into-the-delivered-envelope"

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
    """A caller-set Time and Resources reach the target verbatim, under the EventId PutEvents returned.

    The envelope's time is the past instant sent, resources keep their order, and source,
    detail-type, account, region and detail are the values sent or the caller's own.
    """
    events = ctx.client("events")
    source = _xname(ctx, "src")
    queue = _create_queue(ctx)
    _put_rule_with_sqs_target(ctx, {"source": [source]}, queue)

    partition = queue["arn"].split(":")[1]
    resources = [
        f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:{queue['name']}",
        "sim2real-opaque-resource",
    ]
    when = datetime.datetime(2024, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc)
    detail = {"marker": "carried", "n": 1}
    entry = {
        "Source": source,
        "DetailType": "Sim2realCarried",
        "Detail": json.dumps(detail),
        "Time": when,
        "Resources": resources,
    }

    event_ids: set[str] = set()
    delivered = None
    for _ in range(10):
        resp = events.put_events(Entries=[entry])
        assert resp["FailedEntryCount"] == 0, f"PutEvents refused the entry: {resp['Entries']!r}"
        event_ids.add(resp["Entries"][0]["EventId"])
        got, _ = _wait_for(
            ctx,
            queue["url"],
            lambda b: isinstance(b, dict) and b.get("detail") == detail,
            timeout_s=8.0,
        )
        if got:
            delivered = _body(got[0])
            break
    assert delivered is not None, "the entry was never delivered to the queue"

    assert delivered.get("time") == "2024-03-04T05:06:07Z", (
        f"delivered time is {delivered.get('time')!r}, expected the caller-set '2024-03-04T05:06:07Z'"
    )
    assert delivered.get("resources") == resources, (
        f"delivered resources has {len(delivered.get('resources') or [])} item(s), expected the 2 sent in order"
    )
    assert delivered.get("id") in event_ids, (
        f"delivered id is not one of the {len(event_ids)} EventId(s) PutEvents returned for this entry"
    )
    assert delivered.get("source") == source, f"delivered source is {delivered.get('source')!r}"
    assert delivered.get("detail-type") == "Sim2realCarried", (
        f"delivered detail-type is {delivered.get('detail-type')!r}"
    )
    assert delivered.get("account") == ctx.account, "delivered account is not the caller's account"
    assert delivered.get("region") == ctx.region, f"delivered region is {delivered.get('region')!r}"


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
