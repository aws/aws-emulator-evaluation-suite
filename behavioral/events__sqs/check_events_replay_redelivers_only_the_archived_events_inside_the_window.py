"""events-replay-redelivers-only-the-archived-events-inside-the-window."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-replay-redelivers-only-the-archived-events-inside-the-window"

GROUP = "event-propagation"

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
    """StartReplay re-emits exactly the archived events whose Time falls inside the window, each
    redelivery carrying this replay's replay-name, and excludes an archived event outside it.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-archive.html
    """
    events = ctx.client("events")
    source = _xname(ctx, "src").replace("-", ".")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    queue = _create_queue(ctx)
    rule, rule_arn = _put_rule_with_sqs_target(ctx, {"source": [source]}, queue, bus=bus)

    # Settle the delivery path BEFORE the archive exists, so the warm-up traffic is never archived and
    # cannot pollute the replay window. A fresh rule drops events until it goes live and EventBridge
    # never retries a drop, so a cold path would make the replay's single delivery unprovable.
    _settle_delivery_path(ctx, bus, source, queue["url"], consecutive=2)

    archive = _xname(ctx, "arc")
    archive_arn = events.create_archive(ArchiveName=archive, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: _delete_archive_and_wait(ctx, archive))
    enabled = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
        timeout_s=300.0,
        interval_s=3.0,
        description=f"archive {archive} left CREATING",
    )
    assert enabled["State"] == "ENABLED", (
        f"archive {archive} settled at State={enabled['State']!r}, expected 'ENABLED': {enabled!r}"
    )
    _collect(ctx, queue["url"], window_s=10.0, max_total=200)

    now = datetime.now(timezone.utc)
    inside_time = now - timedelta(hours=1)
    outside_time = now - timedelta(hours=2)
    nonce_a = _xname(ctx, "n-a")
    nonce_b = _xname(ctx, "n-b")
    nonce_c = _xname(ctx, "n-c")
    details = {
        nonce_a: {"nonce": nonce_a, "leg": "inside", "n": 1},
        nonce_b: {"nonce": nonce_b, "leg": "inside", "n": 2},
        nonce_c: {"nonce": nonce_c, "leg": "outside", "n": 3},
    }
    # Windowing is decided by an explicit Time on each entry, not by racing the wall clock.
    resp = events.put_events(
        Entries=[
            {
                "Time": inside_time,
                "Source": source,
                "DetailType": "Replayable",
                "Detail": json.dumps(details[nonce_a]),
                "EventBusName": bus,
            },
            {
                "Time": inside_time,
                "Source": source,
                "DetailType": "Replayable",
                "Detail": json.dumps(details[nonce_b]),
                "EventBusName": bus,
            },
            {
                "Time": outside_time,
                "Source": source,
                "DetailType": "Replayable",
                "Detail": json.dumps(details[nonce_c]),
                "EventBusName": bus,
            },
        ]
    )
    assert resp.get("FailedEntryCount") == 0 and len(resp.get("Entries", [])) == 3, (
        f"PutEvents did not accept all three entries, so nothing below is attributable to the "
        f"replay's window selection: {resp!r}"
    )

    # The live delivery of all three happens now, and it must NOT look like a replay. Draining it
    # here is also what makes every message counted after StartReplay unambiguously a redelivery.
    live: dict[str, dict] = {}
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline and len(live) < 3:
        for msg in _collect(ctx, queue["url"], window_s=10.0, max_total=200):
            body = _body(msg)
            if isinstance(body, dict) and isinstance(body.get("detail"), dict):
                n = body["detail"].get("nonce")
                if n in details:
                    live[n] = body
    assert set(live) == set(details), (
        f"the three published events were not all delivered live, so the queue's reachability at "
        f"replay time is not established: got {sorted(live)!r}, expected {sorted(details)!r}"
    )
    replay_marked = {n: b for n, b in live.items() if "replay-name" in b}
    assert replay_marked == {}, (
        f"a LIVE delivery carried a replay-name field, which would make every redelivery assertion "
        f"below unfalsifiable: {replay_marked!r}"
    )

    # Archive EventCount lags PutEvents by minutes, with no documented bound.
    ingested = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda d: d.get("EventCount", 0) >= 3,
        timeout_s=1500.0,
        interval_s=10.0,
        description=(
            f"archive {archive} ingested all 3 published events (measured on real AWS across four "
            f"runs: 151 s, 353 s, 559 s and once beyond 900 s -- AWS documents no bound, so this "
            f"poll is generous and FAILS on timeout rather than skipping)"
        ),
    )
    assert ingested.get("SizeBytes", 0) > 0, (
        f"the archive counted 3 events but reports SizeBytes={ingested.get('SizeBytes')!r}: nothing "
        f"was stored, so a replay could not re-emit anything"
    )

    # Empty the queue immediately before the replay: every message counted from here came from it.
    _collect(ctx, queue["url"], window_s=15.0, max_total=200)

    replay = _xname(ctx, "replay")
    events.start_replay(
        ReplayName=replay,
        EventSourceArn=archive_arn,
        EventStartTime=inside_time - timedelta(minutes=5),
        EventEndTime=inside_time + timedelta(minutes=5),
        Destination={"Arn": bus_arn, "FilterArns": [rule_arn]},
    )
    # EventBridge exposes no DeleteReplay, so there is no teardown to register; a replay ages out.
    settled = _poll_until(
        lambda: events.describe_replay(ReplayName=replay),
        lambda d: d.get("State") in ("COMPLETED", "FAILED", "CANCELLED", "CANCELLING"),
        timeout_s=400.0,
        interval_s=5.0,
        description=f"replay {replay} reached a terminal state",
    )
    assert settled["State"] == "COMPLETED", (
        f"replay {replay} settled at State={settled['State']!r}, expected 'COMPLETED'; the whole "
        f"replay was {settled!r}"
    )

    redelivered: dict[str, dict] = {}
    strangers: list[Any] = []
    deadline = time.monotonic() + 200.0
    while time.monotonic() < deadline and len(redelivered) < 2:
        for msg in _collect(ctx, queue["url"], window_s=15.0, max_total=200):
            body = _body(msg)
            if not (isinstance(body, dict) and isinstance(body.get("detail"), dict)):
                strangers.append(body)
                continue
            n = body["detail"].get("nonce")
            if n in details:
                redelivered[n] = body
            else:
                strangers.append(body)

    assert set(redelivered) == {nonce_a, nonce_b}, (
        f"the replay over [{(inside_time - timedelta(minutes=5)).isoformat()}, "
        f"{(inside_time + timedelta(minutes=5)).isoformat()}] redelivered "
        f"{sorted(redelivered)!r}, expected exactly {sorted([nonce_a, nonce_b])!r}. "
        f"{nonce_c!r} was archived with a Time two hours in the past, outside that window, so its "
        f"presence would mean the window is not applied and its siblings' absence would mean the "
        f"replay re-emitted nothing"
    )
    assert strangers == [], (
        f"the replay delivered {len(strangers)} message(s) carrying none of this check's nonces, so "
        f"the set equality above was measured against contaminated traffic: {strangers!r}"
    )
    for n, envelope in sorted(redelivered.items()):
        assert envelope.get("replay-name") == replay, (
            f"redelivered event {n!r} carries replay-name={envelope.get('replay-name')!r}, expected "
            f"{replay!r} -- without that field it is indistinguishable from a leftover live "
            f"delivery: {envelope!r}"
        )
        assert envelope["detail"] == details[n], (
            f"redelivered event {n!r} does not carry the payload that was archived: got "
            f"{envelope['detail']!r}, published {details[n]!r}"
        )
        assert envelope.get("source") == source, (
            f"redelivered event {n!r} carries source={envelope.get('source')!r}, expected {source!r}"
        )
        assert envelope.get("detail-type") == "Replayable", (
            f"redelivered event {n!r} carries detail-type={envelope.get('detail-type')!r}, expected "
            f"'Replayable'"
        )
    assert rule in _list_rule_names(events, bus), (
        f"rule {rule!r} is absent from ListRules on bus {bus}, so the FilterArns the replay was "
        f"routed through no longer resolves"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>.

    ArchiveName is capped at 48 characters by real AWS, so archive kinds stay short."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _list_rule_names(events, bus: str) -> list[str]:
    """Every rule name on `bus`, via the botocore paginator ListRules does have."""
    return [
        r["Name"]
        for page in events.get_paginator("list_rules").paginate(EventBusName=bus)
        for r in page.get("Rules", [])
    ]


def _delete_archive_and_wait(ctx, name: str, *, timeout_s: float = 180.0) -> None:
    """Delete an archive and wait for it to be gone; the bus cannot be deleted while an archive
    still references it. Reports failures on stderr instead of raising."""
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
    raise RuntimeError(f"archive {name} still present {timeout_s}s after DeleteArchive; its event bus "
                       f"may fail to delete")


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
    """Drain a queue over a bounded window with long-polling ReceiveMessage; return every message."""
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
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s), max_total=200):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _settle_delivery_path(ctx, bus: str, source: str, queue_url: str, *, consecutive: int = 2) -> None:
    """Emit single control events until `consecutive` of them round-trip back to back.

    A rule and its target become effective progressively and a dropped event is never retried, so
    one arrival proves only that some path is live."""
    events = ctx.client("events")
    streak = 0
    for _ in range(30):
        nonce = _xname(ctx, "warm")
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Warmup",
                    "Detail": json.dumps({"nonce": nonce}),
                    "EventBusName": bus,
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
        f"control events, so a replay's redelivery could not be distinguished from a cold path "
        f"dropping it (longest streak reached: {streak})"
    )


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


def _put_rule_with_sqs_target(ctx, pattern: dict, queue: dict, *, bus: str) -> tuple[str, str]:
    """Create a rule for `pattern` on `bus` targeting `queue`, granting it SendMessage.

    Returns (rule name, rule ARN); the ARN is what a replay's FilterArns needs."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern)
    )["RuleArn"]
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=name, EventBusName=bus, Force=True)
    )
    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn),
    )
    events.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=name, EventBusName=bus, Ids=["t1"], Force=True
        )
    )
    return name, rule_arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
