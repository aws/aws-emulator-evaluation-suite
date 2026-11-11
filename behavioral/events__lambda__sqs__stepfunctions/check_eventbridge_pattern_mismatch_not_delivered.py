"""eventbridge-pattern-mismatch-not-delivered."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-pattern-mismatch-not-delivered"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]


def _put_rule(ctx, pattern, name_hint="rule"):
    events = ctx.client("events")
    rule_name = ctx.unique_name(name_hint)
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _allow_events_to_send(ctx, queue, rule_arn=None):
    """Attach a queue policy allowing events.amazonaws.com to sqs:SendMessage."""
    stmt = {
        "Sid": "AllowEventBridgeSend",
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue["arn"],
    }
    if rule_arn:
        stmt["Condition"] = {"ArnEquals": {"aws:SourceArn": rule_arn}}
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})
        },
    )


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _is_near_miss(body: Any) -> bool:
    """True for any of the three deliberately-non-matching entries this check sends."""
    return isinstance(body, dict) and (
        body.get("detail-type") == "NoMatch"
        or body.get("detail", {}).get("status") == "INACTIVE"
        or body.get("source") == "sim2real.xsvc.pat.extra"
    )


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10):
    """Drain a queue over a bounded window with long-polling ReceiveMessage and return every
    message seen. This is the NEGATIVE observable -- an empty return is only meaningful once a
    positive control has already been observed elsewhere in the check."""
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
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
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


def _emit_until(ctx, entries, queue_url, predicate, *, attempts=10, poll_s=8.0):
    """PutEvents ALL of `entries` together, repeatedly, until a message whose parsed body
    satisfies `predicate` lands on `queue_url`. Returns (matched, others).

    Emitting every leg on every attempt is what makes the negative sound: a freshly created
    rule/target silently drops events until the path goes live and EventBridge never retries a
    dropped event, so the control has to be re-emitted -- and if the near-miss legs ride along on
    each attempt then, by the time the control arrives, every near-miss event has had at least as
    long to arrive as the control did. Non-delivery is therefore suppression, not lag (a
    fixed post-hoc window that is shorter than the control's own eventual-consistency latency would
    score a genuinely-leaking target as clean)."""
    events = ctx.client("events")
    others: list[dict[str, Any]] = []
    for _ in range(attempts):
        resp = events.put_events(Entries=list(entries))
        assert resp["FailedEntryCount"] == 0, resp
        got, extra = _wait_for(ctx, queue_url, predicate, timeout_s=poll_s)
        others.extend(extra)
        if got:
            return got, others
    raise AssertionError(
        f"control event never delivered to {queue_url} after {attempts} PutEvents attempts "
        f"(non-matching messages seen meanwhile: {len(others)}) -- the positive leg of this "
        "negative-delivery check could not be established, so the negative is unprovable"
    )


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three near-miss events (wrong detail-type, wrong nested detail value, extended source) put
    with a matching control are never delivered, while the control arrives with detail.status
    ACTIVE."""
    queue = _create_queue(ctx)
    rule_name, rule_arn = _put_rule(
        ctx,
        {
            "source": ["sim2real.xsvc.pat"],
            "detail-type": ["Match"],
            "detail": {"status": ["ACTIVE"]},
        },
        "rule-pat",
    )
    _allow_events_to_send(ctx, queue, rule_arn)

    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["q"])
    )

    control_marker = ctx.unique_name("control-")
    entries = [
        {
            "Source": "sim2real.xsvc.pat",
            "DetailType": "Match",
            "Detail": json.dumps({"status": "ACTIVE", "marker": control_marker}),
        },
        {
            "Source": "sim2real.xsvc.pat",
            "DetailType": "NoMatch",
            "Detail": json.dumps({"status": "ACTIVE"}),
        },
        {
            "Source": "sim2real.xsvc.pat",
            "DetailType": "Match",
            "Detail": json.dumps({"status": "INACTIVE"}),
        },
        {
            "Source": "sim2real.xsvc.pat.extra",
            "DetailType": "Match",
            "Detail": json.dumps({"status": "ACTIVE"}),
        },
    ]

    control, others = _emit_until(
        ctx,
        entries,
        queue["url"],
        lambda b: isinstance(b, dict)
        and b.get("detail", {}).get("marker") == control_marker,
    )
    assert control, "positive control was never delivered -- the negative is unprovable"
    assert _body(control[0])["detail"]["status"] == "ACTIVE", _body(control[0])

    # One more bounded window past the attempt where the control landed, to catch any near-miss
    # straggler that arrived slower than the control itself.
    others = others + _collect(ctx, queue["url"], window_s=30.0)
    leaked = [b for b in (_body(m) for m in others) if _is_near_miss(b)]

    assert not leaked, (
        "near-miss events were delivered -- event pattern matching is too loose: "
        f"{leaked}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
