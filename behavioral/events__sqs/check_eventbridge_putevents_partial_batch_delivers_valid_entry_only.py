"""eventbridge-putevents-partial-batch-delivers-valid-entry-only."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-putevents-partial-batch-delivers-valid-entry-only"

GROUP = "data-format"

SERVICES = ["events", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A PutEvents batch with one malformed Detail reports FailedEntryCount 1 with MalformedDetail
    and its exact message at that index, while the valid entry gets an EventId and is delivered."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    queue = _create_queue(ctx)

    bus_name = _xname(ctx, "bus")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = _xname(ctx, "rule")
    rule = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": ["sim2real.xsvc.batch"]}),
        State="ENABLED",
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )
    # An SQS target needs a resource policy; without it EventBridge drops the event silently.
    sqs.set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue["arn"],
                            "Condition": {
                                "ArnEquals": {"aws:SourceArn": rule["RuleArn"]}
                            },
                        }
                    ],
                }
            )
        },
    )
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "sqs-target", "Arn": queue["arn"]}],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, EventBusName=bus_name, Ids=["sqs-target"]
        )
    )

    good_marker = _xname(ctx, "good")
    bad_marker = _xname(ctx, "bad")

    def _put_batch():
        return events.put_events(
            Entries=[
                {
                    "Source": "sim2real.xsvc.batch",
                    "DetailType": "BatchProbe",
                    "Detail": json.dumps({"marker": good_marker}),
                    "EventBusName": bus_name,
                },
                {
                    "Source": "sim2real.xsvc.batch",
                    "DetailType": "BatchProbe",
                    # Detail must be a JSON OBJECT string; a bare scalar is malformed.
                    "Detail": f'"{bad_marker}"',
                    "EventBusName": bus_name,
                },
            ]
        )

    resp = _put_batch()
    assert resp["FailedEntryCount"] == 1, (
        f"PutEvents must fail exactly the malformed entry, got FailedEntryCount="
        f"{resp['FailedEntryCount']}: {resp!r}"
    )
    entries = resp["Entries"]
    assert len(entries) == 2, (
        f"Entries must be parallel to the request (2 entries), got {entries!r}"
    )
    # Index alignment is the whole contract: the producer retries by position.
    assert entries[0].get("EventId") and "ErrorCode" not in entries[0], (
        f"the valid entry at index 0 must carry an EventId and no ErrorCode: {entries[0]!r}"
    )
    failed = (entries[1].get("ErrorCode"), entries[1].get("ErrorMessage"))
    assert failed == ("MalformedDetail", _MALFORMED_DETAIL_MESSAGE), (
        f"the malformed entry at index 1 must report ErrorCode MalformedDetail with ErrorMessage "
        f"{_MALFORMED_DETAIL_MESSAGE!r}, got {entries[1]!r}"
    )
    assert "EventId" not in entries[1], (
        f"a failed entry must NOT be assigned an EventId: {entries[1]!r}"
    )

    # Positive half: the valid sibling really was published, not just accounted for. 180s, re-firing
    # each poll: rule/target wiring is not live the instant put_targets returns, and an event
    # published before it is live is dropped.
    def _probe_delivery():
        _put_batch()
        return _drain_queue(ctx, queue["url"], window_s=6.0)

    bodies = _wait_for_effect(
        _probe_delivery,
        lambda bs: any(good_marker in b for b in bs),
        timeout_s=180,
        interval_s=2.0,
        description=f"valid batch entry {good_marker} delivered to the SQS target",
    )
    delivered = [json.loads(b) for b in bodies if good_marker in b]
    assert delivered[0]["detail"] == {"marker": good_marker}, (
        f"delivered detail mangled: {delivered[0]!r}"
    )
    assert delivered[0]["source"] == "sim2real.xsvc.batch", (
        f"delivered source wrong: {delivered[0]['source']!r}"
    )
    # Effect-absent half: the rejected entry must never reach the target.
    assert not [b for b in bodies if bad_marker in b], (
        f"the malformed entry was rejected by PutEvents but still delivered: {bodies!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MALFORMED_DETAIL_MESSAGE = "Detail is malformed."

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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _drain_queue(ctx, queue_url, *, window_s=12.0):
    """Receive-and-delete everything visible on a queue for a bounded window; return raw bodies.

    Used for the effect-ABSENT half of a delivery assertion: an empty return over a bounded
    window is the observable "nothing was delivered", and draining first gives the positive
    half a queue whose contents are attributable to exactly one publish.
    """
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        )
        msgs = resp.get("Messages", [])
        for msg in msgs:
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
