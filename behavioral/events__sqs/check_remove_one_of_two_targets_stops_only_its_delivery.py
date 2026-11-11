"""remove-one-of-two-targets-stops-only-its-delivery."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "remove-one-of-two-targets-stops-only-its-delivery"

GROUP = "targets"

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
    """RemoveTargets of one of a rule's two targets stops delivery to it while the other continues.
    After both queues receive the fan-out, removing t2 leaves exactly t1; A then keeps receiving
    while B gets nothing, and A arriving each round makes B's silence a removal, not lag.
    """
    events = ctx.client("events")
    source = _xname(ctx, "src")
    queue_a = _create_queue(ctx)
    queue_b = _create_queue(ctx)
    rule = _put_rule_with_sqs_target(ctx, {"source": [source]}, queue_a)
    rule_arn = events.describe_rule(Name=rule)["Arn"]
    _set_queue_policy(ctx, queue_b["url"], _allow_service_send(queue_b["arn"], "events.amazonaws.com", rule_arn))
    events.put_targets(Rule=rule, Targets=[{"Id": "t2", "Arn": queue_b["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["t2"]))

    def entry(marker: str) -> dict[str, str]:
        return {"Source": source, "DetailType": "Sim2realRemove", "Detail": json.dumps({"marker": marker})}

    def has(marker: str):
        return lambda b: isinstance(b, dict) and b.get("detail", {}).get("marker") == marker

    on_b, _ = _emit_until(ctx, [entry("both")], queue_b["url"], has("both"))
    assert on_b, "queue B never received the fan-out control"
    on_a, _ = _wait_for(ctx, queue_a["url"], has("both"), timeout_s=60.0)
    assert on_a, "queue A never received the fan-out control that queue B received"

    resp = events.remove_targets(Rule=rule, Ids=["t2"])
    assert resp["FailedEntryCount"] == 0, f"RemoveTargets of t2 reported failures: {resp!r}"
    remaining = [(t["Id"], t["Arn"]) for t in events.list_targets_by_rule(Rule=rule)["Targets"]]
    assert remaining == [("t1", queue_a["arn"])], (
        f"after removing t2 the rule lists {[i for i, _ in remaining]!r}, expected only t1 on queue A"
    )

    converged = None
    history: list[tuple[int, bool, list[Any]]] = []
    for attempt in range(12):
        marker = f"after-remove-{attempt}"
        events.put_events(Entries=[entry(marker)])
        got, _ = _wait_for(ctx, queue_a["url"], has(marker), timeout_s=10.0)
        b_markers = [
            _body(m).get("detail", {}).get("marker") if isinstance(_body(m), dict) else _body(m)
            for m in _collect(ctx, queue_b["url"], window_s=5.0)
        ]
        history.append((attempt, bool(got), b_markers))
        if got and marker not in b_markers:
            converged = attempt
            break
    assert converged is not None, (
        "delivery to the removed target never stopped while its sibling kept delivering; "
        f"per round (attempt, reached A, markers on B): {history!r}"
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
    An empty result proves non-delivery only once a positive control has arrived elsewhere."""
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
    """PutEvents all `entries` together, repeatedly, until one matching `predicate` arrives.
    A new rule/target drops events until live and EventBridge never retries, so every leg is
    re-sent each attempt; non-matching legs then had as long to arrive as the control."""
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
