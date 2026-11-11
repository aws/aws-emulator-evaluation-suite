"""replay-redelivers-each-archived-event-exactly-once-and-never-the-out-of-window-one."""

from __future__ import annotations

import collections
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replay-redelivers-each-archived-event-exactly-once-and-never-the-out-of-window-one"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_SOURCE = "sim2real.nd.replayonce"
_DETAIL_TYPE = "ReplayCardinality"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_queue(ctx, name, *, source_arn_like, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridge",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnLike": {"aws:SourceArn": source_arn_like}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """Long-poll for `seconds`, deleting what it sees. `.get("Messages", [])` feeds a loop whose
    result is asserted by exact count, which is the sanctioned polarity for the empty default."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _put_targets_ok(events, bus, rule, targets):
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _delete_archive(ctx, name):
    try:
        ctx.client("events").delete_archive(ArchiveName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A replay redelivers each archived event exactly once — not zero, not twice — and never
    redelivers the event its window excluded.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_StartReplay.html
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-archive-event.html
    """
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    bus = ctx.unique_name("sim2real-nd-replay-bus-")
    bus_arn = events.create_event_bus(
        Name=bus, Tags=[{"Key": "sim2real-check", "Value": check_tag}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    queue_url, queue_arn = _make_queue(
        ctx,
        f"sim2real-nd-replay-{suffix}",
        source_arn_like=f"arn:*:events:{ctx.region}:{account}:rule/*",
        check_tag=check_tag,
    )

    rule = ctx.unique_name("sim2real-nd-replay-rule-")
    rule_arn = events.put_rule(
        Name=rule,
        EventBusName=bus,
        EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, bus, rule))
    _put_targets_ok(events, bus, rule, [{"Id": "q", "Arn": queue_arn}])

    archive = ctx.unique_name("sim2real-nd-replay-arch-")
    events.create_archive(
        ArchiveName=archive,
        EventSourceArn=bus_arn,
        EventPattern=json.dumps({"source": [_SOURCE]}),
        RetentionDays=1,
    )
    ctx.on_cleanup(lambda: _delete_archive(ctx, archive))
    enabled = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda a: a["State"] in ("ENABLED", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=5,
        description=f"archive {archive} settled out of CREATING",
    )
    assert enabled["State"] == "ENABLED", (
        f"archive {archive} settled at State={enabled['State']!r} "
        f"({enabled.get('StateReason')!r}), expected 'ENABLED' — nothing can be replayed from an "
        f"archive that never came up"
    )

    inside = [f"inside-a-{suffix}", f"inside-b-{suffix}"]
    outside = f"outside-{suffix}"

    # Phase 1: the two events that will fall INSIDE the replay window.
    t0 = time.monotonic()
    boundary_open = datetime.now(timezone.utc) - timedelta(seconds=30)
    resp = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": n}),
            }
            for n in inside
        ]
    )
    assert resp.get("FailedEntryCount") == 0, (
        f"PutEvents did not accept both inside-window entries, so nothing below is attributable: "
        f"{resp!r}"
    )

    # The live delivery is the positive control on this exact rule->queue wiring and it MEASURES L.
    # Accumulate ACROSS polling windows, not just within the latest one: `_drain` deletes every
    # message it sees, so if the two entries from one PutEvents call happen to land in separate
    # 6s windows, checking only the latest window's batch loses the earlier arrival forever and
    # spuriously times out a target that delivered correctly, just not within a single window.
    live_by_nonce: dict[str, dict] = {}
    _deadline = time.monotonic() + 180.0
    while time.monotonic() < _deadline and set(live_by_nonce) < set(inside):
        for msg in _drain(ctx, queue_url, seconds=6):
            live_by_nonce[msg["detail"]["nonce"]] = msg
    latency = max(time.monotonic() - t0, 1.0)
    live = list(live_by_nonce.values())
    assert set(live_by_nonce) == set(inside), (
        f"the live delivery reached {sorted(live_by_nonce)!r} within 180s, expected exactly "
        f"{sorted(inside)!r} — a contaminated or incomplete queue makes every count below "
        f"meaningless"
    )
    assert not [m for m in live if "replay-name" in m], (
        f"a LIVE delivery already carries a replay-name field, which would make the replay "
        f"attribution below unfalsifiable: "
        f"{[m for m in live if 'replay-name' in m][:1]!r}"
    )

    # Phase 2: the event that will fall OUTSIDE the window. The exclusion is STRUCTURAL — the
    # replay's EventEndTime is fixed before this event exists, so no wait decides it.
    boundary_close = datetime.now(timezone.utc)
    # Not a barrier and not a sleep: a bounded wait on the LIVE clock so the next event's
    # archived `time` is unambiguously after EventEndTime even at second granularity. It raises if
    # the clock does not advance, which is itself a finding.
    _poll_until(
        lambda: datetime.now(timezone.utc),
        lambda now: now >= boundary_close + timedelta(seconds=2),
        timeout_s=30,
        interval_s=0.5,
        description=(
            f"the wall clock advanced past EventEndTime {boundary_close.isoformat()} by 2s before "
            f"the out-of-window event was published"
        ),
    )
    resp_out = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": outside}),
            }
        ]
    )
    assert resp_out.get("FailedEntryCount") == 0, (
        f"PutEvents did not accept the outside-window entry: {resp_out!r}"
    )
    live_out = _poll_until(
        lambda: _drain(ctx, queue_url, seconds=6),
        lambda msgs: any(m["detail"]["nonce"] == outside for m in msgs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the outside-window event {outside!r} was delivered LIVE — proof it EXISTS and was "
            f"archivable, so its later absence is an exclusion and not a lost event"
        ),
    )
    assert any(m["detail"]["nonce"] == outside for m in live_out), (
        f"the outside-window event never arrived live: {live_out!r}"
    )

    ingested = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda a: a.get("EventCount", 0) >= 3,
        timeout_s=1500,
        interval_s=10,
        description=(
            f"archive {archive} counted all three published events (measured on real AWS: the "
            f"sibling check on this same archive->replay path saw EventCount lag PutEvents by "
            f"151s/353s/559s/900s+ across four runs, so this poll is generous and FAILS on "
            f"timeout rather than truncating early)"
        ),
    )
    assert ingested.get("SizeBytes", 0) > 0, (
        f"archive {archive} reports EventCount={ingested.get('EventCount')!r} but "
        f"SizeBytes={ingested.get('SizeBytes')!r} — nothing was stored, so a replay could not "
        f"re-emit anything and the cardinality claims below would be vacuous"
    )

    # Phase 3: replay only the window that contains the two inside events.
    replay = ctx.unique_name("sim2real-nd-replay-")
    events.start_replay(
        ReplayName=replay,
        EventSourceArn=ingested["ArchiveArn"],
        EventStartTime=boundary_open,
        EventEndTime=boundary_close,
        Destination={"Arn": bus_arn, "FilterArns": [rule_arn]},
    )
    settled = _poll_until(
        lambda: events.describe_replay(ReplayName=replay),
        lambda r: r["State"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=300,
        interval_s=5,
        description=f"replay {replay} reached a terminal state",
    )
    assert settled["State"] == "COMPLETED", (
        f"replay {replay} settled at State={settled['State']!r} "
        f"({settled.get('StateReason')!r}), expected 'COMPLETED'"
    )

    # Phase 4: the cardinality claim. Drain for 3L AFTER the replay is COMPLETED, so a correct but
    # slower target is not graded as having blocked, and a duplicate has time to show up.
    hold = max(3 * latency, 15.0)
    redelivered = _drain(ctx, queue_url, seconds=hold)
    counts = collections.Counter(m["detail"]["nonce"] for m in redelivered)
    assert counts.get(outside, 0) == 0, (
        f"the replay over [{boundary_open.isoformat()}, {boundary_close.isoformat()}] redelivered "
        f"the out-of-window event {outside!r} {counts.get(outside)} time(s) during a {hold:.0f}s "
        f"drain, expected 0 — its archived `time` is after EventEndTime"
    )
    for nonce in inside:
        assert counts.get(nonce, 0) == 1, (
            f"the replay redelivered {nonce!r} {counts.get(nonce, 0)} time(s) over a {hold:.0f}s "
            f"drain (3x the {latency:.0f}s measured live latency), expected EXACTLY 1 — 0 means the "
            f"replay re-emitted nothing, >1 means it is at-least-once where this asserts once. All "
            f"counts: {dict(counts)!r}"
        )
    strangers = [m for m in redelivered if m["detail"]["nonce"] not in set(inside) | {outside}]
    assert strangers == [], (
        f"{len(strangers)} redelivered message(s) carry none of this check's nonces, so the exact "
        f"counts above were measured against contaminated traffic: {strangers[:2]!r}"
    )
    for msg in redelivered:
        assert msg.get("replay-name") == replay, (
            f"redelivered event {msg['detail']['nonce']!r} carries "
            f"replay-name={msg.get('replay-name')!r}, expected {replay!r} — without that marker it "
            f"is indistinguishable from a late LIVE delivery, and 'exactly once' would be measured "
            f"over the wrong population"
        )

    # A second independent observable, plus a freeze: a COMPLETED replay is terminal.
    assert _queue_depth(ctx, queue_url) == 0, (
        f"the queue reports depth {_queue_depth(ctx, queue_url)} behind an empty receive — a second "
        f"replayed copy is in flight, so 'exactly once' is not stable"
    )
    tail = _drain(ctx, queue_url, seconds=max(latency, 15.0))
    assert tail == [], (
        f"{len(tail)} further message(s) arrived after the COMPLETED replay's drain: "
        f"{[m['detail']['nonce'] for m in tail]!r} — a terminal replay must not keep emitting"
    )


def _teardown_rule(ctx, bus, rule):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"], Force=True)
    events.delete_rule(Name=rule, EventBusName=bus, Force=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
