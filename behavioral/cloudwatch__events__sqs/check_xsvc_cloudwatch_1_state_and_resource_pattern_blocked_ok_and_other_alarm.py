"""xsvc-cloudwatch-1-state-and-resource-pattern-blocked-ok-and-other-alarm."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-1-state-and-resource-pattern-blocked-ok-and-other-alarm"
GROUP = "event-filtering"
SERVICES = ["cloudwatch", "events", "sqs"]

_SOURCE = "aws.cloudwatch"
_DETAIL_TYPE = "CloudWatch Alarm State Change"
_PERIOD = 10  # high-resolution alarm: the evaluator runs per 10 s bucket
_THRESHOLD = 50.0
_HIGH = 90.0
_LOW = 10.0


_POLL_BUDGET_S = 240.0  # a ceiling for a poll to FAIL at; never asserted as a latency


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _now_bucket():
    epoch = int(time.time())
    return datetime.fromtimestamp(epoch - epoch % _PERIOD, tz=timezone.utc)


def _wait_for_bucket(bucket):
    """Block until the wall clock is inside `bucket`, so a value lands in a fresh period."""
    while datetime.now(timezone.utc) < bucket:
        time.sleep(0.5)


def _put(cw, namespace, metric, bucket, value):
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric, "Timestamp": bucket, "Value": value, "StorageResolution": 1}
        ],
    )


def _describe(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["MetricAlarm"]
    ):
        for a in page.get("MetricAlarms", []):
            if a["AlarmName"] == name:
                return a
    raise AssertionError(f"alarm {name!r} is not present in DescribeAlarms")


def _create_alarm(ctx, cw, name, namespace, metric):
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription=f"sim2real {CHECK}",
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        Period=_PERIOD,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: ctx.client("cloudwatch").delete_alarms(AlarmNames=[n]))
    return _describe(cw, name)["AlarmArn"]


def _make_queue(ctx, name):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _allow_rule_to_send(ctx, url, queue_arn, rule_arn):
    """Least privilege: events.amazonaws.com may SendMessage ONLY on behalf of this one rule."""
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowOneRule",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )


def _make_rule(ctx, name, pattern, target_ids):
    events = ctx.client("events")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, name, target_ids))
    return arn


def _teardown_rule(ctx, name, target_ids):
    events = ctx.client("events")
    events.remove_targets(Rule=name, Ids=target_ids, Force=True)
    events.delete_rule(Name=name, Force=True)


def _put_targets_ok(events, rule, targets):
    resp = events.put_targets(Rule=rule, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _drain_into(ctx, url, inbox, *, seconds, until=None):
    """Receive-and-delete into `inbox` for `seconds`, or until `until(inbox)` holds."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            inbox.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if until is not None and until(inbox):
            break
    return inbox


def _events_for(inbox, arns):
    """(resource, state) -> event for events naming one of `arns`, de-duplicated by event id."""
    by_id = {}
    for e in inbox:
        res = e.get("resources") or []
        if any(a in res for a in arns):
            by_id.setdefault(e["id"], e)
    return sorted(by_id.values(), key=lambda e: e["detail"]["state"]["timestamp"])


def _key(e):
    return (e["resources"][0], e["detail"]["state"]["value"])


def _await_keys(ctx, url, inbox, arns, want, what):
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    while True:
        _drain_into(ctx, url, inbox, seconds=4,
                    until=lambda ib: want <= {_key(e) for e in _events_for(ib, arns)})
        got = {_key(e) for e in _events_for(inbox, arns)}
        if want <= got:
            return _events_for(inbox, arns)
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what}: delivered {sorted(got)!r}, still missing {sorted(want - got)!r}"
            )


def _drive_until(ctx, cw, alarms, publish, want, what):
    """Keep publishing and polling until every alarm in `alarms` is `want`; FAIL on exhaustion."""
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    while True:
        publish()
        states = {a: _describe(cw, a)["StateValue"] for a in alarms}
        if all(s == want for s in states.values()):
            return states
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} never happened; last states {states!r}")
        time.sleep(2.0)


def _rule_live_barrier(ctx, cw, canary, delivered, what):
    """Toggle a canary alarm via SetAlarmState until any canary event is delivered.

    A new EventBridge rule is eventually consistent and has no 'live' flag; an event sent right
    after PutTargets can be lost."""
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    flips = 0
    while True:
        cw.set_alarm_state(
            AlarmName=canary,
            StateValue=("ALARM", "OK")[flips % 2],
            StateReason="sim2real rule-liveness barrier",
        )
        flips += 1
        if delivered():
            return flips
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what}: no canary event delivered after {flips} transitions")


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A rule on resources [alarmA] AND state ALARM delivers alarmA's ALARM transition only.

    It blocks alarmA's OK and alarmB's ALARM, each one field away from the match.
    """
    cw = ctx.client("cloudwatch")
    events = ctx.client("events")
    namespace = ctx.unique_name("Sim2RealXsvcCw1Filter")
    alarm_a = ctx.unique_name("sim2real-xsvc-cw1-flt-a-")
    alarm_b = ctx.unique_name("sim2real-xsvc-cw1-flt-b-")
    canary = ctx.unique_name("sim2real-xsvc-cw1-flt-canary-")

    # Alarms first: the filtered pattern needs alarmA's ARN. No data yet, so no transition yet.
    arn_a = _create_alarm(ctx, cw, alarm_a, namespace, "LoadA")
    arn_b = _create_alarm(ctx, cw, alarm_b, namespace, "LoadB")
    canary_arn = _create_alarm(ctx, cw, canary, namespace, "Canary")

    f_url, f_arn = _make_queue(ctx, ctx.unique_name("sim2real-xsvc-cw1-flt-f-"))
    w_url, w_arn = _make_queue(ctx, ctx.unique_name("sim2real-xsvc-cw1-flt-w-"))

    # Filtered rule created BEFORE the wide one, so the wide rule's liveness bounds it.
    f_rule = ctx.unique_name("sim2real-xsvc-cw1-flt-fr-")
    f_pattern = {
        "source": [_SOURCE],
        "detail-type": [_DETAIL_TYPE],
        "resources": [arn_a],
        "detail": {"state": {"value": ["ALARM"]}},
    }
    f_rule_arn = _make_rule(ctx, f_rule, f_pattern, ["f"])
    _allow_rule_to_send(ctx, f_url, f_arn, f_rule_arn)
    _put_targets_ok(events, f_rule, [{"Id": "f", "Arn": f_arn}])

    w_rule = ctx.unique_name("sim2real-xsvc-cw1-flt-wr-")
    w_rule_arn = _make_rule(ctx, w_rule, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}, ["w"])
    _allow_rule_to_send(ctx, w_url, w_arn, w_rule_arn)
    _put_targets_ok(events, w_rule, [{"Id": "w", "Arn": w_arn}])

    w_inbox: list = []
    f_inbox: list = []

    # Barrier 0: the wide rule is live before any real transition can happen.
    _rule_live_barrier(
        ctx,
        cw,
        canary,
        lambda: bool(_events_for(_drain_into(
            ctx, w_url, w_inbox, seconds=4,
            until=lambda ib: bool(_events_for(ib, [canary_arn]))), [canary_arn])),
        "the wide rule becoming live",
    )
    cw.delete_alarms(AlarmNames=[canary])

    # Real data: both alarms breach together.
    high = set()

    def publish_both_high():
        b = _now_bucket()
        _put(cw, namespace, "LoadA", b, _HIGH)
        _put(cw, namespace, "LoadB", b, _HIGH)
        high.add(b)

    _drive_until(ctx, cw, [alarm_a, alarm_b], publish_both_high, "ALARM", "alarmA and alarmB in ALARM")
    # Recovering data is already stored for the next bucket when it opens, so alarmA never sees an
    # empty period (which would move it to INSUFFICIENT_DATA before OK).
    first_low = max(high) + timedelta(seconds=_PERIOD)
    _put(cw, namespace, "LoadA", first_low, _LOW)
    _wait_for_bucket(first_low)

    def publish_a_low():
        b = _now_bucket()
        if b not in high:
            _put(cw, namespace, "LoadA", b, _LOW)

    _drive_until(ctx, cw, [alarm_a], publish_a_low, "OK", "alarmA back to OK")

    # A wide control rule sees the same events; its delivery of all three is the barrier that
    # keeps the filtered queue's absence from being a race.
    wanted = {(arn_a, "ALARM"), (arn_b, "ALARM"), (arn_a, "OK")}
    w_events = _await_keys(ctx, w_url, w_inbox, [arn_a, arn_b], wanted, "the wide control rule")
    w_by_key = {_key(e): e for e in w_events}
    w_a_alarm, w_b_alarm, w_a_ok = (w_by_key[k] for k in
                                    ((arn_a, "ALARM"), (arn_b, "ALARM"), (arn_a, "OK")))

    # The blocked events really are one field away from the match (proved on the W copies).
    assert w_b_alarm["detail"]["state"]["value"] == "ALARM" and w_b_alarm["resources"] == [arn_b], (
        f"alarmB's wide-rule copy {w_b_alarm['resources']!r}/"
        f"{w_b_alarm['detail']['state']['value']!r} is not an ALARM event naming alarmB"
    )
    assert w_a_ok["resources"] == [arn_a] and w_a_ok["detail"]["state"]["value"] == "OK", (
        f"alarmA's OK wide-rule copy {w_a_ok['resources']!r}/"
        f"{w_a_ok['detail']['state']['value']!r} is not an OK event naming alarmA"
    )
    assert w_a_ok["detail"]["previousState"]["value"] == "ALARM", (
        f"alarmA's OK event previousState {w_a_ok['detail']['previousState']['value']!r}"
    )

    # Positive control: F delivers alarmA's ALARM, the same routed event W got.
    _await_keys(ctx, f_url, f_inbox, [arn_a, arn_b], {(arn_a, "ALARM")}, "the filtered rule (control)")
    # W has delivered all three events; a fixed hold then bounds any late F copy.
    hold = 10.0
    _drain_into(ctx, f_url, f_inbox, seconds=hold)

    f_ids = sorted({e["id"] for e in f_inbox})
    assert f_ids == [w_a_alarm["id"]], (
        f"the filtered queue holds event ids {f_ids!r}, expected exactly alarmA's ALARM event "
        f"{w_a_alarm['id']!r}; delivered {[(_key(e), e['id']) for e in f_inbox]!r}"
    )
    f_keys = sorted({_key(e) for e in f_inbox})
    assert (arn_a, "OK") not in f_keys, (
        f"alarmA's OK transition reached the queue filtered on state ALARM: {f_keys!r} — the "
        f"detail.state.value filter was not applied"
    )
    assert all(k[0] != arn_b for k in f_keys), (
        f"alarmB's ALARM reached the queue filtered on resources [alarmA]: {f_keys!r} — the "
        f"resources filter was not applied"
    )
    f_event = f_inbox[0]
    assert f_event["detail"]["alarmName"] == alarm_a, f"alarmName {f_event['detail']['alarmName']!r}"
    assert f_event == w_a_alarm, (
        f"the filtered copy {f_event!r} differs from the wide-rule copy {w_a_alarm!r} of the same "
        f"event"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
