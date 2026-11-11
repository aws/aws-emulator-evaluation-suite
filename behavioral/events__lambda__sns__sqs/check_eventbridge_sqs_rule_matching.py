"""eventbridge-sqs-rule-matching."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-sqs-rule-matching"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge delivers matching events to the SQS target and drops non-matching ones."""
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    rule_name = ctx.unique_name("rule-sqs-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["test.sqs"], "detail-type": ["ItemCreated"]}
        ),
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    match_entry = {
        "Source": "test.sqs",
        "DetailType": "ItemCreated",
        "Detail": json.dumps({"id": "eb-sqs-1"}),
    }
    nonmatch_entry = {
        "Source": "test.other",
        "DetailType": "Unrelated",
        "Detail": json.dumps({"id": "eb-sqs-2"}),
    }

    collected: list[dict] = []

    def drain() -> None:
        resp = sqs.receive_message(
            QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            collected.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue["url"], ReceiptHandle=m["ReceiptHandle"])

    # Rule activation is eventually consistent, so re-publish both entries on every
    # poll. Same-round publishing keeps the negative assertion fair: the non-matching
    # event always had an equal opportunity to be delivered.
    def probe():
        events.put_events(Entries=[match_entry, nonmatch_entry])
        drain()
        return collected

    started = time.monotonic()
    _wait_for_effect(probe, lambda c: len(c) > 0, timeout_s=90, interval_s=5.0)
    match_latency_s = time.monotonic() - started

    # Hold the absence window for >=3x the measured positive-control latency on this
    # same wiring, re-draining instead of sleeping blind, so a late/incorrect
    # non-matching delivery is not missed and a correct-but-slower target is not
    # scored as having blocked it.
    grace_deadline = time.monotonic() + max(30.0, match_latency_s * 3)
    while time.monotonic() < grace_deadline:
        drain()
        remaining = grace_deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5.0, remaining))

    assert any(b.get("detail", {}).get("id") == "eb-sqs-1" for b in collected), (
        "matching EventBridge event never reached the SQS target"
    )
    assert not any(b.get("detail", {}).get("id") == "eb-sqs-2" for b in collected), (
        "non-matching event should not have been delivered"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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
