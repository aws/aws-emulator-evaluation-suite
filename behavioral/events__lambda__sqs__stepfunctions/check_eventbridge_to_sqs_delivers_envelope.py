"""eventbridge-to-sqs-delivers-envelope."""

from __future__ import annotations

import datetime
import json
import re
import time
from typing import Any

from behavioral_harness import tags

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

CHECK = "eventbridge-to-sqs-delivers-envelope"

GROUP = "event-propagation"

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


def _put_events_until(ctx, entries, probe, timeout_s=75, interval_s=6):
    """PutEvents repeatedly until a downstream effect appears.

    Rule/target creation on the default bus is eventually consistent: an event
    published immediately after PutTargets can be silently dropped. Republishing
    while polling makes the positive path deterministic.
    """
    events = ctx.client("events")

    def attempt():
        resp = events.put_events(Entries=entries)
        assert resp["FailedEntryCount"] == 0, resp
        return probe()

    return _poll_until(
        attempt, lambda r: bool(r), timeout_s=timeout_s, interval_s=interval_s
    )


def _receive_raw(ctx, queue_url, max_messages=10):
    resp = ctx.client("sqs").receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        WaitTimeSeconds=5,
        MessageAttributeNames=["All"],
    )
    return resp.get("Messages", [])


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """EB rule + queue policy delivers the complete event envelope to SQS."""
    queue = _create_queue(ctx)
    rule_name, rule_arn = _put_rule(
        ctx,
        {"source": ["sim2real.xsvc.sqs"], "detail-type": ["OrderPlaced"]},
        "rule-sqs",
    )
    _allow_events_to_send(ctx, queue, rule_arn)

    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["q"])
    )

    publish_start = time.monotonic()
    timeout_s = 60
    msgs = _put_events_until(
        ctx,
        [
            {
                "Source": "sim2real.xsvc.sqs",
                "DetailType": "OrderPlaced",
                "Detail": json.dumps({"orderId": "o-1", "amount": 42}),
            }
        ],
        lambda: _receive_raw(ctx, queue["url"]),
        timeout_s=timeout_s,
    )
    elapsed_s = time.monotonic() - publish_start
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    body = json.loads(msgs[0]["Body"])
    assert body["source"] == "sim2real.xsvc.sqs", body
    assert body["detail-type"] == "OrderPlaced", body
    assert body["detail"]["orderId"] == "o-1", body
    assert body["detail"]["amount"] == 42, body
    assert body["version"] == "0", f"envelope version: {body}"
    assert body["resources"] == [], f"envelope resources: {body}"
    assert body["region"] == ctx.region, f"envelope region: {body}"
    assert body["account"] == account_id, f"envelope account: {body}"
    assert _UUID_RE.match(body["id"]), f"envelope id not a UUID: {body}"

    event_time = datetime.datetime.strptime(
        body["time"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    # The event was published sometime during the publish/poll window; allow a
    # generous margin either side for clock skew and republish retries.
    skew_s = (now - event_time).total_seconds()
    assert -30 <= skew_s <= elapsed_s + 30, (
        f"envelope time {body['time']} is not within the publish window "
        f"(elapsed={elapsed_s:.1f}s, skew={skew_s:.1f}s): {body}"
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
