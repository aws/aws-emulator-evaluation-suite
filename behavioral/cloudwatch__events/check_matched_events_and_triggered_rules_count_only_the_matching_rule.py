"""matched-events-and-triggered-rules-count-only-the-matching-rule."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "matched-events-and-triggered-rules-count-only-the-matching-rule"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "events"]

#: 10x the ~1-minute EventBridge publication cadence, measured stable well within one poll.
_METRIC_BUDGET_S = 600.0
#: How long the non-matching twin's absence is held, once the matching rule's own datapoint has
#: settled: 3x the publication cadence plus the settle margin.
_ABSENCE_HOLD_S = 180.0
_DELIVERY_BUDGET_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """One event on a custom bus with a matching and a non-matching rule counts MatchedEvents == 1
    and TriggeredRules == 1 under the matching rule's {EventBusName, RuleName} series only, while
    the twin rule, after the event demonstrably reached the consumer, accounts for nothing."""
    events = ctx.client("events")
    cw = ctx.client("cloudwatch")

    bus_name = ctx.unique_name("sim2real-cwev-bus-")
    events.create_event_bus(
        Name=bus_name,
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__events"}, {"Key": "check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    queue_url, queue_arn = _queue_open_to_events(ctx)

    matching_source = ctx.unique_name("sim2real.match.")
    other_source = ctx.unique_name("sim2real.nomatch.")
    detail_type = "sim2real-cwev-probe"

    # Two rules on ONE bus, created in the same instant, differing ONLY in the source they pin.
    hit_rule = _rule(ctx, events, bus_name, "hit-", matching_source, detail_type, queue_arn)
    miss_rule = _rule(ctx, events, bus_name, "miss-", other_source, detail_type, queue_arn)

    # ---- one event, matching exactly one of the two rules ------------------------------------- #
    put = events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": matching_source,
                "DetailType": detail_type,
                "Detail": json.dumps({"probe": CHECK}),
            }
        ]
    )
    assert put["FailedEntryCount"] == 0, (
        f"PutEvents refused the entry ({put!r}); no metric total below would then be attributable "
        f"to this check"
    )
    event_id = put["Entries"][0]["EventId"]

    # ---- leg 1: it really matched, and only once. Read at the CONSUMER. ----------------------- #
    bodies = _drain_until(
        ctx,
        queue_url,
        want=1,
        timeout_s=_DELIVERY_BUDGET_S,
        description=f"the event from rule {hit_rule} arriving on the target queue",
    )
    assert len(bodies) == 1, (
        f"the target queue received {len(bodies)} messages for one published event: {bodies!r}. "
        f"Two arrivals mean BOTH rules matched, and the twin's metric absence asserted below would "
        f"be measuring the wrong thing"
    )
    delivered = json.loads(bodies[0])
    assert delivered.get("source") == matching_source, (
        f"the delivered envelope names source {delivered.get('source')!r}, expected "
        f"{matching_source!r}: {delivered!r}"
    )
    assert delivered.get("id") == event_id, (
        f"the delivered envelope carries id {delivered.get('id')!r}, expected the id PutEvents "
        f"returned, {event_id!r}: {delivered!r}"
    )

    # ---- leg 2: the terminal read, at CloudWatch ---------------------------------------------- #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=20)

    def _dps(metric: str, dims: list[dict]) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/Events",
            MetricName=metric,
            Dimensions=dims,
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]

    def _sum(metric: str, dims: list[dict]) -> float | None:
        dps = _dps(metric, dims)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    hit_dim = [
        {"Name": "EventBusName", "Value": bus_name},
        {"Name": "RuleName", "Value": hit_rule},
    ]
    miss_dim = [
        {"Name": "EventBusName", "Value": bus_name},
        {"Name": "RuleName", "Value": miss_rule},
    ]

    # Stability rather than "poll until >= 1": a one-sided poll stops looking the instant the target
    # is met and so can only detect an under-count, while the failure mode here (fan-out to every
    # rule) is an OVER-count.
    #
    # Both metrics are read under the SAME {EventBusName, RuleName} series: on a custom bus AWS
    # publishes MatchedEvents only under that combined set, not under {EventBusName},
    # {RuleName} or {EventSourceName} alone.
    matched, triggered = _poll_until_stable(
        lambda: _pair(_sum("MatchedEvents", hit_dim), _sum("TriggeredRules", hit_dim)),
        window_s=120.0,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=2.0,
        description=(
            f"AWS/Events MatchedEvents and TriggeredRules for EventBusName={bus_name}, "
            f"RuleName={hit_rule} settling on one value"
        ),
    )
    assert matched == 1.0, (
        f"AWS/Events MatchedEvents Sum for EventBusName={bus_name}, RuleName={hit_rule} settled at "
        f"{matched!r}, expected 1.0 — this check published exactly one entry to this bus, and "
        f"exactly one of its two rules pins that entry's source"
    )
    assert triggered == 1.0, (
        f"AWS/Events TriggeredRules Sum for RuleName={hit_rule} on EventBusName={bus_name} settled "
        f"at {triggered!r}, expected 1.0 for the single matching event"
    )

    for metric, dims in (("MatchedEvents", hit_dim), ("TriggeredRules", hit_dim)):
        dps = _dps(metric, dims)
        assert dps, f"AWS/Events {metric} under {dims!r} vanished on re-read: {dps!r}"
        units = {d.get("Unit") for d in dps}
        assert units == {"Count"}, (
            f"AWS/Events {metric} datapoints under {dims!r} carry Unit(s) {units!r}, expected "
            f"exactly {{'Count'}}"
        )

    published = _dimension_sets(cw, "AWS/Events", "RuleName", hit_rule)
    assert ("EventBusName", "RuleName") in published, (
        f"ListMetrics reports dimension sets {sorted(published)!r} for the AWS/Events series naming "
        f"RuleName={hit_rule}; a rule on a CUSTOM bus must publish the two-dimension "
        f"('EventBusName', 'RuleName') series, because that is what separates one customer's bus "
        f"from the default bus in a shared account"
    )

    # ---- leg 3: the twin accounts for nothing, held after the positive settled ---------------- #
    _assert_stays(
        lambda: _sum("TriggeredRules", miss_dim),
        None,
        hold_s=_ABSENCE_HOLD_S,
        interval_s=2.0,
        description=(
            f"the non-matching twin rule {miss_rule}, on the same bus and pointed at the same "
            f"queue, accounts for no AWS/Events TriggeredRules datapoint"
        ),
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    final = _sum("TriggeredRules", hit_dim)
    assert final == 1.0, (
        f"after the twin's absence window the matching rule's TriggeredRules Sum read {final!r}, "
        f"expected 1.0 — the absence above is only meaningful while the positive series is served"
    )


# ===== helpers =====
def _pair(a, b):
    """A complete (a, b) tuple, or None if either half has not arrived yet."""
    return None if a is None or b is None else (a, b)


def _rule(ctx, events, bus: str, label: str, source: str, detail_type: str, target_arn: str) -> str:
    name = ctx.unique_name(f"sim2real-cwev-{label}")
    events.put_rule(
        Name=name,
        EventBusName=bus,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__events"}],
    )
    events.put_targets(
        Rule=name, EventBusName=bus, Targets=[{"Id": "sink", "Arn": target_arn}]
    )
    # Reverse dependency order: targets must go before the rule.
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=bus))
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=name, EventBusName=bus, Ids=["sink"])
    )
    return name


def _queue_open_to_events(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwev-q-"),
        tags={"sim2real": "cloudwatch__events"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    account = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain_until(ctx, queue_url: str, *, want: int, timeout_s: float, description: str) -> list[str]:
    """Collect message bodies until *want* have arrived, then keep draining for a further quarter of
    the budget so a SECOND arrival cannot slip past a single-shot read. Raises on the deadline."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    bodies: list[str] = []
    settled_at: float | None = None
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if len(bodies) >= want:
            if settled_at is None:
                settled_at = time.monotonic()
            elif time.monotonic() - settled_at >= timeout_s / 4:
                return bodies
    if len(bodies) >= want:
        return bodies
    raise AssertionError(
        f"{description}: only {len(bodies)} of {want} messages arrived within {timeout_s}s; "
        f"bodies were {bodies!r}"
    )


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=2.0, description="reading"):
    """Return probe()'s value once two readings >= window_s apart are EQUAL and complete."""
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


def _assert_stays(probe, expected, *, hold_s, interval_s=2.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
