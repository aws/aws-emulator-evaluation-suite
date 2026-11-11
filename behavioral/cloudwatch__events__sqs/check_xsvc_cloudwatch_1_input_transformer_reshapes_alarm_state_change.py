"""xsvc-cloudwatch-1-input-transformer-reshapes-alarm-state-change."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-1-input-transformer-reshapes-alarm-state-change"
GROUP = "event-transformation"
SERVICES = ["cloudwatch", "events", "sqs"]

_SOURCE = "aws.cloudwatch"
_DETAIL_TYPE = "CloudWatch Alarm State Change"
_PERIOD = 10  # high-resolution alarm: the evaluator runs per 10 s bucket
_THRESHOLD = 50.0
_HIGH = 90.0
_LOW = 10.0
_METRIC = "Load"

_PATHS = {
    "alarm": "$.detail.alarmName",
    "to": "$.detail.state.value",
    "from": "$.detail.previousState.value",
    "account": "$.account",
    "region": "$.region",
    "resource": "$.resources[0]",
    "eventId": "$.id",
    "period": "$.detail.configuration.metrics[0].metricStat.period",
}
# JSON template: string variables are inserted quoted, numbers stay numbers.
_JSON_TEMPLATE = (
    '{"kind":"sim2real-alarm-transition","alarm":<alarm>,"from":<from>,"to":<to>,'
    '"account":<account>,"region":<region>,"resource":<resource>,"eventId":<eventId>,'
    '"period":<period>,"rule":"<aws.events.rule-name>"}'
)
# A quoted text template is delivered WITH its surrounding double quotes.
_TEXT_TEMPLATE = '"<alarm> moved from <from> to <to> via <aws.events.rule-name>"'


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


def _put(cw, namespace, bucket, value):
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": _METRIC, "Timestamp": bucket, "Value": value, "StorageResolution": 1}
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


def _create_alarm(ctx, cw, name, namespace):
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription=f"sim2real {CHECK}",
        Namespace=namespace,
        MetricName=_METRIC,
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


def _drain_into(ctx, url, inbox, *, seconds):
    """Receive-and-delete for `seconds`, appending raw bodies to `inbox`."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            inbox.append(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return inbox


def _await(ctx, url, inbox, select, count, what):
    """Drain until select(inbox) has `count` distinct items; FAIL on exhaustion."""
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    while True:
        _drain_into(ctx, url, inbox, seconds=2)
        got = select(inbox)
        if len(got) >= count:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what}: got {len(got)} of {count}: {got!r}")


def _drive_until(ctx, cw, alarm, publish, want, what):
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    while True:
        publish()
        state = _describe(cw, alarm)
        if state["StateValue"] == want:
            return state
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what} never happened; last state {state['StateValue']!r} "
                f"reason {state['StateReason']!r}"
            )
        time.sleep(2.0)


def _raw_events(bodies, arn):
    by_id = {}
    for b in bodies:
        e = json.loads(b)
        if e.get("resources") == [arn]:
            by_id.setdefault(e["id"], e)
    return sorted(by_id.values(), key=lambda e: e["detail"]["state"]["timestamp"])


def _json_bodies(bodies, alarm):
    out = {}
    for b in bodies:
        d = json.loads(b)
        if isinstance(d, dict) and d.get("alarm") == alarm:
            out.setdefault(d.get("eventId"), d)
    return out


def _text_bodies(bodies, alarm):
    return sorted({b for b in bodies if b.startswith(f'"{alarm} ')})


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
    "axis:happy-path",
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
    """Each alarm transition reaches a raw, a JSON-transformed and a text-transformed SQS target.

    The transformed bodies are exactly the templates rendered from the raw event's own values.
    """
    cw = ctx.client("cloudwatch")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    namespace = ctx.unique_name("Sim2RealXsvcCw1Xform")
    alarm = ctx.unique_name("sim2real-xsvc-cw1-xf-")
    canary = ctx.unique_name("sim2real-xsvc-cw1-xf-canary-")

    raw_url, raw_arn = _make_queue(ctx, ctx.unique_name("sim2real-xsvc-cw1-xf-raw-"))
    json_url, json_arn = _make_queue(ctx, ctx.unique_name("sim2real-xsvc-cw1-xf-json-"))
    text_url, text_arn = _make_queue(ctx, ctx.unique_name("sim2real-xsvc-cw1-xf-text-"))

    rule = ctx.unique_name("sim2real-xsvc-cw1-xf-r-")
    rule_arn = _make_rule(
        ctx, rule, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}, ["raw", "json", "text"]
    )
    for url, arn in ((raw_url, raw_arn), (json_url, json_arn), (text_url, text_arn)):
        _allow_rule_to_send(ctx, url, arn, rule_arn)
    _put_targets_ok(
        events,
        rule,
        [
            {"Id": "raw", "Arn": raw_arn},
            {
                "Id": "json",
                "Arn": json_arn,
                "InputTransformer": {"InputPathsMap": _PATHS, "InputTemplate": _JSON_TEMPLATE},
            },
            {
                "Id": "text",
                "Arn": text_arn,
                "InputTransformer": {"InputPathsMap": _PATHS, "InputTemplate": _TEXT_TEMPLATE},
            },
        ],
    )
    raw_in: list = []
    json_in: list = []
    text_in: list = []

    # The rule must be live before the first real transition, or that event is lost.
    canary_arn = _create_alarm(ctx, cw, canary, namespace + "Canary")
    _rule_live_barrier(
        ctx,
        cw,
        canary,
        lambda: bool(_raw_events(_drain_into(ctx, raw_url, raw_in, seconds=2), canary_arn)),
        "the rule becoming live",
    )
    cw.delete_alarms(AlarmNames=[canary])

    alarm_arn = _create_alarm(ctx, cw, alarm, namespace)
    high = set()

    def publish_high():
        b = _now_bucket()
        _put(cw, namespace, b, _HIGH)
        high.add(b)

    _drive_until(ctx, cw, alarm, publish_high, "ALARM", "breaching data driving ALARM")
    # Recovering data is already stored for the next bucket when it opens, so no period is empty
    # (an empty period would move a missing-data alarm to INSUFFICIENT_DATA first).
    first_low = max(high) + timedelta(seconds=_PERIOD)
    _put(cw, namespace, first_low, _LOW)
    _wait_for_bucket(first_low)

    def publish_low():
        b = _now_bucket()
        if b not in high:
            _put(cw, namespace, b, _LOW)

    _drive_until(ctx, cw, alarm, publish_low, "OK", "recovering data driving OK")
    # Deleting the alarm once it is OK keeps a later silent period from adding OK -> INSUFFICIENT_DATA.
    cw.delete_alarms(AlarmNames=[alarm])

    raw = _await(ctx, raw_url, raw_in, lambda b: _raw_events(b, alarm_arn), 2, "raw target")
    jsn = _await(ctx, json_url, json_in, lambda b: _json_bodies(b, alarm), 2, "JSON target")
    txt = _await(ctx, text_url, text_in, lambda b: _text_bodies(b, alarm), 2, "text target")

    transitions = [
        (e["detail"]["previousState"]["value"], e["detail"]["state"]["value"]) for e in raw
    ]
    assert transitions == [("INSUFFICIENT_DATA", "ALARM"), ("ALARM", "OK")], (
        f"the raw target saw transitions {transitions!r} for {alarm}"
    )
    for e in raw:
        assert (e["source"], e["detail-type"], e["account"], e["region"]) == (
            _SOURCE, _DETAIL_TYPE, account, ctx.region
        ), f"raw envelope {e!r}"

    # JSON template: exact object per raw event, nothing more, types preserved.
    expected_json = {
        e["id"]: {
            "kind": "sim2real-alarm-transition",
            "alarm": e["detail"]["alarmName"],
            "from": e["detail"]["previousState"]["value"],
            "to": e["detail"]["state"]["value"],
            "account": e["account"],
            "region": e["region"],
            "resource": e["resources"][0],
            "eventId": e["id"],
            "period": e["detail"]["configuration"]["metrics"][0]["metricStat"]["period"],
            "rule": rule,
        }
        for e in raw
    }
    assert jsn == expected_json, (
        f"the JSON-transformed bodies {jsn!r} are not the template rendered from the raw events "
        f"{expected_json!r}"
    )
    for body in jsn.values():
        assert type(body["period"]) is int and body["period"] == _PERIOD, (
            f"period rendered as {body['period']!r} ({type(body['period']).__name__}); the path "
            f"selects the number {_PERIOD}"
        )
        assert (body["account"], body["region"], body["resource"]) == (
            account, ctx.region, alarm_arn
        ), f"JSON body {body!r} did not substitute the real account/region/alarm ARN"
        assert not {"detail-type", "source", "detail", "resources", "id"} & set(body), (
            f"the JSON target received envelope keys {sorted(body)!r}, not the transformed shape"
        )
    assert sorted((b["from"], b["to"]) for b in jsn.values()) == sorted(transitions), (
        f"JSON bodies carry transitions {[(b['from'], b['to']) for b in jsn.values()]!r}"
    )

    # Text template: exact strings, surrounding quotes included.
    expected_text = sorted(
        f'"{alarm} moved from {frm} to {to} via {rule}"' for frm, to in transitions
    )
    assert txt == expected_text, (
        f"the text-transformed bodies {txt!r} are not {expected_text!r}"
    )
    assert all(not b.lstrip('"').startswith("{") for b in txt), (
        f"a text-target body is a JSON object, not the rendered string: {txt!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
