"""xsvc-cloudwatch-2-state-changes-tagging-and-noop-puts-emit-no-configuration-change-event."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-2-state-changes-tagging-and-noop-puts-emit-no-configuration-change-event"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_CONFIG = "CloudWatch Alarm Configuration Change"
_STATE = "CloudWatch Alarm State Change"
_NAMESPACE = "Sim2Real/XsvcCw2"
_METRIC = "EmitScopeProbe"


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


def _make_queue(ctx, name, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _make_rule(ctx, name, alarm_names, queue_url, queue_arn, check_tag):
    """A rule on BOTH alarm detail-types, so a State Change is observable beside the absence of a
    Configuration Change for the same act."""
    events = ctx.client("events")
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": [_CONFIG, _STATE],
        "detail": {"alarmName": list(alarm_names)},
    }
    rule_arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, name))
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowThisRule",
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
    resp = events.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue_arn}])
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {name} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, name):
    events = ctx.client("events")
    events.remove_targets(Rule=name, Ids=["q"], Force=True)
    events.delete_rule(Name=name, Force=True)


def _drain(ctx, url, *, seconds):
    """Receive and delete for up to `seconds`."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _alarm_kwargs(name, threshold, actions_enabled):
    return dict(
        AlarmName=name,
        Namespace=_NAMESPACE,
        MetricName=_METRIC,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=float(threshold),
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=actions_enabled,
        TreatMissingData="missing",
    )


def _signature(event):
    d = event.get("detail", {})
    return (
        event.get("detail-type"),
        d.get("operation"),
        (d.get("configuration") or {}).get("actionsEnabled"),
        (d.get("previousConfiguration") or {}).get("actionsEnabled"),
        (d.get("state") or {}).get("value") if event.get("detail-type") == _STATE else None,
    )


def _prove_path_live(ctx, url, name, put, *, streak=5, timeout_s=180):
    """Warm up until `streak` consecutive writes each deliver their own event; returns the count.

    A new rule propagates host by host with no completion signal: one that already delivered an
    event can still drop the next, so any miss resets the streak."""
    deadline = time.monotonic() + timeout_s
    n, run_len, history = 0, 0, []
    while run_len < streak:
        assert time.monotonic() < deadline, (
            f"the rule->queue path for {name!r} never delivered {streak} consecutive warm-up events "
            f"within {timeout_s}s (delivered per write: {history!r})"
        )
        n += 1
        put(n)
        seen = False
        until = time.monotonic() + 8
        while time.monotonic() < until and not seen:
            for m in _drain(ctx, url, seconds=2):
                d = m.get("detail", {})
                conf = d.get("configuration") or {}
                if d.get("alarmName") == name and conf.get("threshold") == float(n):
                    seen = True
        run_len = run_len + 1 if seen else 0
        history.append(seen)
    return n


def _unique_by_id(events):
    """EventBridge delivers at least once: a redelivery carries the SAME `id`, so it is one event."""
    return list({e["id"]: e for e in events}.values())


@tags("axis:negative-delivery", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Of six alarm writes, only create, DisableAlarmActions and EnableAlarmActions emit a
    Configuration Change; SetAlarmState emits only a State Change, TagResource and a no-op put none.
    """
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = "xsvc-cloudwatch-2-emit-scope"
    suffix = uuid.uuid4().hex[:10]
    alarm = ctx.unique_name("sim2real-xsvc-cw2-scope-")
    warm = ctx.unique_name("sim2real-xsvc-cw2-swarm-")
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{alarm}"

    url, qarn = _make_queue(ctx, f"sim2real-xsvc-cw2-scope-{suffix}", check_tag)
    _make_rule(ctx, ctx.unique_name("sim2real-xsvc-cw2-scope-"), [alarm, warm], url, qarn, check_tag)

    # Warm-up on a separate alarm until the rule->queue path is proven live.
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[warm]))
    _prove_path_live(ctx, url, warm, lambda n: cw.put_metric_alarm(**_alarm_kwargs(warm, n, False)))

    # The six writes. Expected events are annotated per call.
    cw.put_metric_alarm(**_alarm_kwargs(alarm, 5, True))  # -> config create
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))
    cw.disable_alarm_actions(AlarmNames=[alarm])  # -> config update, actionsEnabled True -> False
    cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM", StateReason="sim2real forced")  # -> state
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "sim2real-check", "Value": check_tag}])  # none
    cw.put_metric_alarm(**_alarm_kwargs(alarm, 5, False))  # identical to current -> none
    described = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"]
    assert [(a["AlarmArn"], a["ActionsEnabled"], a["StateValue"]) for a in described] == [
        (alarm_arn, False, "ALARM")
    ], (
        f"before the barrier the alarm reads {[(a.get('AlarmArn'), a.get('ActionsEnabled'), a.get('StateValue')) for a in described]!r}, "
        f"expected [({alarm_arn!r}, False, 'ALARM')] — the no-op put must not reset the forced state"
    )
    cw.enable_alarm_actions(AlarmNames=[alarm])  # -> config update, False -> True: THE BARRIER

    seen = []

    def _collect():
        seen.extend(m for m in _drain(ctx, url, seconds=5) if m["detail"].get("alarmName") == alarm)
        return seen

    barrier = (_CONFIG, "update", True, False, None)
    t0 = time.monotonic()
    _poll_until(
        _collect,
        lambda msgs: barrier in [_signature(m) for m in msgs] and len(msgs) >= 4,
        timeout_s=120,
        interval_s=0,
        description=(
            f"the EnableAlarmActions update (the barrier) and the three earlier events reached {url} "
            f"(so far: {[_signature(m) for m in seen]!r})"
        ),
    )
    # Hold past the barrier, bounded by what the barrier itself measured.
    _drain_more = _drain(ctx, url, seconds=max(2 * (time.monotonic() - t0), 15.0))
    seen.extend(m for m in _drain_more if m["detail"].get("alarmName") == alarm)

    # The evaluator may legitimately RECLAIM the forced state (ALARM -> INSUFFICIENT_DATA, no data) at
    # its next minute tick; that is a State Change caused by evaluation, not by any of the six writes,
    # so exactly that transition is excluded — every Configuration Change stays in the comparison.
    seen = _unique_by_id(seen)
    reclaims = [m for m in seen if _signature(m) == (_STATE, None, None, None, "INSUFFICIENT_DATA")]
    assert len(reclaims) <= 1, f"{len(reclaims)} reclaim State Changes, expected at most 1"
    # Arrival order is not call order, so the stream is compared as a multiset.
    got = sorted((_signature(m) for m in seen if m not in reclaims), key=repr)
    want = sorted(
        [
            (_CONFIG, "create", True, None, None),
            (_CONFIG, "update", False, True, None),
            (_STATE, None, None, None, "ALARM"),
            (_CONFIG, "update", True, False, None),
        ],
        key=repr,
    )
    assert got == want, (
        f"the alarm's event stream was {got!r}, expected exactly {want!r} — SetAlarmState must emit "
        f"only a State Change, and TagResource / an identical PutMetricAlarm must emit nothing"
    )
    for m in seen:
        assert m.get("resources") == [alarm_arn] and m.get("source") == "aws.cloudwatch", (
            f"event {_signature(m)!r} names resources={m.get('resources')!r} "
            f"source={m.get('source')!r}, expected [{alarm_arn!r}] / 'aws.cloudwatch'"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
