"""events-archive-replay-reaches-a-rule-created-after-the-events-were-archived."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-archive-replay-reaches-a-rule-created-after-the-events-were-archived"

GROUP = "archive-replay"

SERVICES = ["events", "sqs"]


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A replay routes archived events through the rules as they exist now: a rule created after
    archival receives the replayed event, tagged with `replay-name` and keeping its original `time`.
    """
    events = ctx.client("events")
    source = _xname(ctx, "src").replace("-", ".")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    archive = _xname(ctx, "arc")
    archive_arn = events.create_archive(
        ArchiveName=archive, EventSourceArn=bus_arn, EventPattern=json.dumps({"source": [source]})
    )["ArchiveArn"]
    ctx.on_cleanup(lambda: _delete_archive_and_wait(ctx, archive))
    enabled = _wait_archive_enabled(events, archive, timeout_s=_budget_s(ctx, 300.0), ctx=ctx)
    assert enabled.get("EventCount") == 0, (
        f"archive {archive} reported EventCount={enabled.get('EventCount')!r} before any event was "
        f"published: {enabled!r}"
    )

    # An hour in the past, so current-time warm-up events are archived but never fall in the
    # replay window.
    event_time = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
    nonce = _xname(ctx, "n")
    detail = {"nonce": nonce, "leg": "archived-before-the-rule"}
    resp = events.put_events(
        Entries=[
            {
                "Time": event_time,
                "Source": source,
                "DetailType": "Replayable",
                "Detail": json.dumps(detail),
                "EventBusName": bus,
            }
        ]
    )
    assert resp.get("FailedEntryCount") == 0 and resp["Entries"][0].get("EventId"), (
        f"PutEvents did not accept the entry, so nothing below is attributable to the archive: {resp!r}"
    )

    ingested = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda d: d.get("EventCount", 0) >= 1,
        timeout_s=_budget_s(ctx, 1500.0),
        interval_s=1.0,
        description=(
            f"archive {archive} ingested the published event (real AWS measured 151 s to beyond "
            f"900 s for this lag; AWS documents no bound)"
        ),
        ctx=ctx,
    )
    assert ingested.get("SizeBytes", 0) > 0, (
        f"the archive counted the event but reports SizeBytes={ingested.get('SizeBytes')!r}: {ingested!r}"
    )

    # No customer rule may exist yet. AWS adds a managed Events-Archive-<archive> rule for the
    # archive's own ingest, which is excluded without requiring it.
    rules_before = [r for r in _list_rule_names(events, bus) if r != f"Events-Archive-{archive}"]
    assert rules_before == [], (
        f"bus {bus} (created by this check) already had customer rules {rules_before!r} when the "
        f"event was archived, so the late-rule premise does not hold"
    )

    queue = _create_queue(ctx)
    rule, rule_arn = _put_rule_with_sqs_target(ctx, bus, {"source": [source]}, queue)
    warm_seen = _settle_delivery_path(ctx, bus, source, queue["url"], consecutive=2)
    leaked_live = [b for b in warm_seen if _nonce_of(b) == nonce]
    assert leaked_live == [], (
        f"the archived event {nonce!r} reached the late rule's queue BEFORE any replay, so it was "
        f"delivered live to a rule that did not exist when it was put: {leaked_live!r}"
    )
    drained = [_body(m) for m in _collect(ctx, queue["url"], window_s=10.0, max_total=200)]
    assert not [b for b in drained if _nonce_of(b) == nonce], (
        f"the archived event {nonce!r} reached the late rule's queue before the replay: {drained!r}"
    )

    replay = _xname(ctx, "replay")
    events.start_replay(
        ReplayName=replay,
        EventSourceArn=archive_arn,
        EventStartTime=event_time - timedelta(minutes=5),
        EventEndTime=event_time + timedelta(minutes=5),
        Destination={"Arn": bus_arn, "FilterArns": [rule_arn]},
    )
    # EventBridge has no DeleteReplay, so a replay needs no teardown.
    settled = _poll_until(
        lambda: events.describe_replay(ReplayName=replay),
        lambda d: d.get("State") in ("COMPLETED", "FAILED", "CANCELLED", "CANCELLING"),
        timeout_s=_budget_s(ctx, 400.0),
        interval_s=1.0,
        description=f"replay {replay} reached a terminal state",
        ctx=ctx,
    )
    assert settled["State"] == "COMPLETED", (
        f"replay {replay} settled at State={settled['State']!r}, expected 'COMPLETED': {settled!r}"
    )

    matched, others = _wait_for(
        ctx, queue["url"], lambda b: _nonce_of(b) == nonce, timeout_s=_budget_s(ctx, 200.0)
    )
    if not matched and _budget_spent(ctx):
        raise TimeoutError(f"the replayed event {nonce!r} on the queue: the run budget ended first; not graded")
    # Anything else the replay re-emitted lands alongside the match; drain a fixed window for the
    # stray check.
    others += _collect(ctx, queue["url"], window_s=8.0, max_total=200)
    assert matched, (
        f"replay {replay} COMPLETED but the archived event {nonce!r} never reached rule {rule!r}, "
        f"which was created after the event was archived. Messages seen instead: "
        f"{[_body(m) for m in others]!r}"
    )
    envelope = _body(matched[0])
    assert envelope.get("replay-name") == replay, (
        f"the redelivered event carries replay-name={envelope.get('replay-name')!r}, expected "
        f"{replay!r}: {envelope!r}"
    )
    assert envelope.get("detail") == detail, (
        f"the redelivered event's detail is {envelope.get('detail')!r}, the archived one was {detail!r}"
    )
    expected_time = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert envelope.get("time") == expected_time, (
        f"the redelivered event carries time={envelope.get('time')!r}; a replay must keep the "
        f"archived event's own time {expected_time!r}, not stamp the replay's: {envelope!r}"
    )
    assert envelope.get("source") == source, (
        f"the redelivered event carries source={envelope.get('source')!r}, expected {source!r}"
    )
    stray_replays = [
        _body(m) for m in others
        if isinstance(_body(m), dict) and "replay-name" in _body(m) and _nonce_of(_body(m)) != nonce
    ]
    assert stray_replays == [], (
        f"the replay also re-emitted events outside its window (the current-time warm-ups): "
        f"{stray_replays!r}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(max(0.0, min(interval_s, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_archive_enabled(events, name: str, *, timeout_s: float = 300.0, ctx=None) -> dict:
    d = _poll_until(
        lambda: events.describe_archive(ArchiveName=name),
        lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"archive {name} left CREATING",
        ctx=ctx,
    )
    assert d["State"] == "ENABLED", f"archive {name} settled at State={d['State']!r}: {d!r}"
    return d


def _delete_archive_and_wait(ctx, name: str, *, timeout_s: float = 180.0) -> None:
    """Delete an archive and wait for it to be gone: the bus cannot be deleted while an archive
    still references it."""
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
    """Poll a queue until a batch holds a message matching predicate(), deleting every one seen."""
    sqs = ctx.client("sqs")
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        wait = min(2, max(0, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            (matched if predicate(_body(msg)) else others).append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
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
