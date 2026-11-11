"""events-archive-replay-does-not-redeliver-to-a-rule-outside-filter-arns."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-archive-replay-does-not-redeliver-to-a-rule-outside-filter-arns"

GROUP = "archive-replay"

SERVICES = ["events", "sqs"]


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A replay whose Destination.FilterArns names rule A re-emits to A only.

    Rule B, matching the same event and proven live, receives nothing from the replay.
    """
    events = ctx.client("events")
    source = _xname(ctx, "src").replace("-", ".")
    pattern = {"source": [source]}

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    queue_a = _create_queue(ctx)
    rule_a, rule_a_arn = _put_rule_with_sqs_target(ctx, bus, pattern, queue_a)
    queue_b = _create_queue(ctx)
    rule_b, rule_b_arn = _put_rule_with_sqs_target(ctx, bus, pattern, queue_b)
    assert rule_a_arn != rule_b_arn, f"two rules share an ARN: {rule_a_arn!r}"

    # Settle both delivery paths BEFORE the archive exists, so no warm-up is archived.
    _settle_delivery_path(ctx, bus, source, queue_a["url"], consecutive=2)
    _settle_delivery_path(ctx, bus, source, queue_b["url"], consecutive=2)

    archive = _xname(ctx, "arc")
    archive_arn = events.create_archive(
        ArchiveName=archive, EventSourceArn=bus_arn, EventPattern=json.dumps(pattern)
    )["ArchiveArn"]
    ctx.on_cleanup(lambda: _delete_archive_and_wait(ctx, archive))
    _wait_archive_enabled(events, archive)
    _collect(ctx, queue_a["url"], window_s=8.0, max_total=200)
    _collect(ctx, queue_b["url"], window_s=8.0, max_total=200)

    event_time = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
    nonce = _xname(ctx, "n")
    detail = {"nonce": nonce, "leg": "archived"}
    resp = events.put_events(
        Entries=[{"Time": event_time, "Source": source, "DetailType": "Replayable",
                  "Detail": json.dumps(detail), "EventBusName": bus}]
    )
    assert resp.get("FailedEntryCount") == 0 and resp["Entries"][0].get("EventId"), (
        f"PutEvents did not accept the entry: {resp!r}"
    )

    # Positive control 1: the LIVE event reaches BOTH rules.
    for label, q in (("A", queue_a), ("B", queue_b)):
        got, _ = _wait_for(ctx, q["url"], lambda b: _nonce_of(b) == nonce, timeout_s=180.0)
        assert got, f"the live event {nonce!r} never reached rule {label}'s queue, so B's silence later proves nothing"
        live = _body(got[0])
        assert "replay-name" not in live, f"a LIVE delivery to rule {label} carried replay-name: {live!r}"

    ingested = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda d: d.get("EventCount", 0) >= 1,
        timeout_s=1500.0,
        interval_s=10.0,
        description=(
            f"archive {archive} ingested the published event (real AWS measured 151 s to beyond "
            f"900 s for this lag; AWS documents no bound)"
        ),
    )
    assert ingested.get("SizeBytes", 0) > 0, f"archive counted the event but stored nothing: {ingested!r}"

    # Every message counted from here on came from the replay (or the post-control).
    _collect(ctx, queue_a["url"], window_s=10.0, max_total=200)
    _collect(ctx, queue_b["url"], window_s=10.0, max_total=200)

    replay = _xname(ctx, "replay")
    events.start_replay(
        ReplayName=replay,
        EventSourceArn=archive_arn,
        EventStartTime=event_time - timedelta(minutes=5),
        EventEndTime=event_time + timedelta(minutes=5),
        Destination={"Arn": bus_arn, "FilterArns": [rule_a_arn]},
    )
    # No DeleteReplay API exists, so the replay job cannot be cleaned up.
    settled = _poll_until(
        lambda: events.describe_replay(ReplayName=replay),
        lambda d: d.get("State") in ("COMPLETED", "FAILED", "CANCELLED", "CANCELLING"),
        timeout_s=400.0,
        interval_s=5.0,
        description=f"replay {replay} reached a terminal state",
    )
    assert settled["State"] == "COMPLETED", f"replay {replay} settled at {settled['State']!r}: {settled!r}"
    assert settled.get("Destination", {}).get("FilterArns") == [rule_a_arn], (
        f"DescribeReplay reports FilterArns={settled.get('Destination')!r}, expected only {rule_a_arn!r}"
    )

    # Positive control 2 (and the barrier): the replay reaches A.
    got_a, _ = _wait_for(ctx, queue_a["url"], lambda b: _nonce_of(b) == nonce, timeout_s=200.0)
    assert got_a, f"replay {replay} COMPLETED but never reached rule A ({rule_a}), the rule it named"
    replayed = _body(got_a[0])
    assert replayed.get("replay-name") == replay, (
        f"rule A's redelivery carries replay-name={replayed.get('replay-name')!r}, expected {replay!r}"
    )

    # A's receipt of the replay is the barrier that anchors B's hold window.
    held = [_body(m) for m in _collect(ctx, queue_b["url"], window_s=60.0, max_total=200)]
    assert held == [], (
        f"rule B ({rule_b}) is not in the replay's FilterArns, yet its queue received {len(held)} "
        f"message(s) after the replay reached rule A: {held!r}"
    )

    # Positive control 3: B's path is still live right after the hold.
    post = _xname(ctx, "post")
    events.put_events(
        Entries=[{"Source": source, "DetailType": "PostControl", "Detail": json.dumps({"nonce": post}),
                  "EventBusName": bus}]
    )
    got_b, _ = _wait_for(ctx, queue_b["url"], lambda b: _nonce_of(b) == post, timeout_s=180.0)
    assert got_b, (
        f"a fresh live event never reached rule B after the hold, so B's silence during the replay "
        f"may be a dead path rather than FilterArns"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name. ArchiveName is capped at 48 characters by real AWS,
    so kinds stay short."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _nonce_of(body: Any) -> Any:
    if isinstance(body, dict) and isinstance(body.get("detail"), dict):
        return body["detail"].get("nonce")
    return None


def _list_rule_names(events, bus: str) -> list[str]:
    return [
        r["Name"]
        for page in events.get_paginator("list_rules").paginate(EventBusName=bus)
        for r in page.get("Rules", [])
    ]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_archive_enabled(events, name: str) -> dict:
    d = _poll_until(
        lambda: events.describe_archive(ArchiveName=name),
        lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
        timeout_s=300.0,
        interval_s=3.0,
        description=f"archive {name} left CREATING",
    )
    assert d["State"] == "ENABLED", f"archive {name} settled at State={d['State']!r}: {d!r}"
    return d


def _delete_archive_and_wait(ctx, name: str, *, timeout_s: float = 180.0) -> None:
    """Delete an archive and WAIT for it to be gone: the bus cannot be deleted while an archive still
    references it."""
    events = ctx.client("events")
    try:
        events.delete_archive(ArchiveName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete archive {name}: {exc}") from exc
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(3)
    raise RuntimeError(f"archive {name} still present {timeout_s}s after DeleteArchive")


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _put_rule_with_sqs_target(ctx, bus: str, pattern: dict, queue: dict) -> tuple[str, str]:
    """A rule on `bus` with `pattern`, targeting `queue`, with a SourceArn-scoped queue policy.
    Teardown is registered so targets are removed before the rule is deleted (LIFO)."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED",
        Tags=_xsvc_tags_kv(),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus, Force=True))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"], Force=True))
    assert put.get("FailedEntryCount") == 0, f"PutTargets rejected the SQS target: {put!r}"
    return rule, rule_arn


def _body(msg: dict):
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10):
    """Drain a queue over a bounded window and return EVERY message seen (deleting each)."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s), max_total=200):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _settle_delivery_path(ctx, bus: str, source: str, queue_url: str, *, consecutive: int = 2) -> list:
    """Emit single current-time control events until `consecutive` round-trip back to back; return
    every body seen on the queue meanwhile. A fresh rule becomes effective progressively and a dropped
    event is never retried, so this polls the control's own arrival rather than sleeping."""
    events = ctx.client("events")
    streak = 0
    seen: list[Any] = []
    for _ in range(30):
        n = _xname(ctx, "warm")
        events.put_events(
            Entries=[{"Source": source, "DetailType": "Warmup", "Detail": json.dumps({"nonce": n}),
                      "EventBusName": bus}]
        )
        got, rest = _wait_for(ctx, queue_url, lambda b, n=n: _nonce_of(b) == n, timeout_s=15.0)
        seen.extend(_body(m) for m in got + rest)
        streak = streak + 1 if got else 0
        if streak >= consecutive:
            return seen
    raise AssertionError(
        f"the rule -> {queue_url} delivery path never round-tripped {consecutive} consecutive control "
        f"events (longest streak {streak})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
