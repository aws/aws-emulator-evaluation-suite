"""xsvc-cloudwatch-2-rejected-composite-alarm-emits-no-configuration-change-event."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-2-rejected-composite-alarm-emits-no-configuration-change-event"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_DETAIL_TYPE = "CloudWatch Alarm Configuration Change"
_NAMESPACE = "Sim2Real/XsvcCw2"
_METRIC = "CompositeChildProbe"


class _Succeeded:
    """Returned by `_error` when the call it was given did NOT fail — never a falsy string, so
    an emulator that accepts what AWS rejects reads as exactly that."""

    def __init__(self, response):
        self.response = response

    def __repr__(self):
        return f"<call unexpectedly SUCCEEDED: {str(self.response)[:200]}>"


def _error(fn):
    """(code, message) of the ClientError `fn` raises, or `_Succeeded` when it does not raise."""
    try:
        return _Succeeded(fn())
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


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
    events = ctx.client("events")
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": [_DETAIL_TYPE],
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
    return rule_arn


def _teardown_rule(ctx, name):
    events = ctx.client("events")
    events.remove_targets(Rule=name, Ids=["q"], Force=True)
    events.delete_rule(Name=name, Force=True)


def _drain(ctx, url, *, seconds):
    """Receive and delete for up to `seconds`. `.get("Messages", [])` feeds a list whose content is
    asserted by exact value below — the sanctioned polarity for an empty default."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _put_child(cw, name, threshold):
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=_NAMESPACE,
        MetricName=_METRIC,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=float(threshold),
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        ActionsEnabled=False,
        TreatMissingData="missing",
    )


def _prove_path_live(ctx, url, name, put, *, streak=5, timeout_s=180):
    """A new rule (and a new queue policy) propagates host by host and no API reports completion.
    A rule that had already delivered one event can drop the next one ~7 s
    later, and the dropped event never arrived (420 s window) although an independent rule saw it.
    So the path counts as live only after `streak` CONSECUTIVE warm-up writes each delivered their
    own event, matched by threshold; any miss resets the count. Returns the writes it took."""
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


# ===== the check =====
@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A PutCompositeAlarm naming a nonexistent alarm fails with the exact ValidationError and emits
    no event, while the valid composite then emits create, update and delete events carrying the
    alarmRule in force."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = "xsvc-cloudwatch-2-composite-rejected"
    suffix = uuid.uuid4().hex[:10]

    child = ctx.unique_name("sim2real-xsvc-cw2-child-")
    composite = ctx.unique_name("sim2real-xsvc-cw2-comp-")
    missing = f"sim2real-xsvc-cw2-absent-{suffix}"  # deliberately never created
    composite_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{composite}"

    url, qarn = _make_queue(ctx, f"sim2real-xsvc-cw2-comp-{suffix}", check_tag)
    _make_rule(ctx, ctx.unique_name("sim2real-xsvc-cw2-comp-"), [child, composite], url, qarn, check_tag)

    # Warm-up AND prerequisite: the child is needed for the valid composite, and its own events prove
    # the rule->queue path is live before anything about the composite is asserted.
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[child]))
    _prove_path_live(ctx, url, child, lambda n: _put_child(cw, child, n))

    # THE BREAK: a composite whose rule names an alarm that does not exist.
    bad_rule = f'ALARM("{child}") AND ALARM("{missing}")'
    err = _error(
        lambda: cw.put_composite_alarm(AlarmName=composite, AlarmRule=bad_rule, ActionsEnabled=False)
    )
    if isinstance(err, _Succeeded):
        ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[composite]))
    expected = (
        "ValidationError",
        f"Could not save the composite alarm as alarms "
        f"[arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{missing}] in the alarm rule do not exist",
    )
    assert err == expected, (
        f"PutCompositeAlarm naming the nonexistent alarm {missing!r} returned {err!r}, expected "
        f"{expected!r}"
    )
    after_reject = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])
    assert after_reject["CompositeAlarms"] == [], (
        f"the rejected PutCompositeAlarm still created {composite!r}: "
        f"{after_reject['CompositeAlarms']!r}"
    )

    # POSITIVE CONTROL under the same name: create, update the rule, delete.
    good_rule = f'ALARM("{child}")'
    new_rule = f'ALARM("{child}") OR INSUFFICIENT_DATA("{child}")'
    cw.put_composite_alarm(
        AlarmName=composite, AlarmRule=good_rule, ActionsEnabled=False,
        AlarmDescription="sim2real xsvc-cloudwatch-2 composite",
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[composite]))
    described = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])
    assert [a["AlarmArn"] for a in described["CompositeAlarms"]] == [composite_arn], (
        f"DescribeAlarms for {composite!r} returned "
        f"{[a.get('AlarmArn') for a in described['CompositeAlarms']]!r}, expected [{composite_arn!r}]"
    )
    collected = []

    def _await_op(op):
        """Drain until the composite's `op` event has arrived; every composite event is kept."""

        def _probe():
            collected.extend(
                m for m in _drain(ctx, url, seconds=4)
                if m.get("detail", {}).get("alarmName") == composite
            )
            return [m.get("detail", {}).get("operation") for m in collected]

        _poll_until(
            _probe,
            lambda ops_so_far: op in ops_so_far,
            timeout_s=90,
            interval_s=0,
            description=f"the rule scoped to {composite} received the {op!r} event (operations so far)",
        )

    # Each write waits for its own event before the next, so every event is attributable to one call.
    _await_op("create")
    cw.put_composite_alarm(
        AlarmName=composite, AlarmRule=new_rule, ActionsEnabled=False,
        AlarmDescription="sim2real xsvc-cloudwatch-2 composite",
    )
    _await_op("update")
    cw.delete_alarms(AlarmNames=[composite])
    _await_op("delete")
    collected.extend(  # one more pass: a 4th composite event would be the rejected write leaking
        m for m in _drain(ctx, url, seconds=6)
        if m.get("detail", {}).get("alarmName") == composite
    )
    collected = _unique_by_id(collected)
    ops = [m["detail"]["operation"] for m in collected]
    assert ops == ["create", "update", "delete"], (
        f"the composite {composite!r} produced operations {ops!r}, expected exactly "
        f"['create', 'update', 'delete'] — an extra event before 'create' means the REJECTED "
        f"PutCompositeAlarm emitted one"
    )
    leaked = [m for m in collected if missing in json.dumps(m)]
    assert leaked == [], (
        f"{len(leaked)} event(s) mention the nonexistent alarm {missing!r}, i.e. the rejected rule "
        f"reached the bus: {leaked!r}"
    )
    by_op = {m["detail"]["operation"]: m for m in collected}
    expected_rule = {"create": good_rule, "update": new_rule, "delete": new_rule}
    for op, event in by_op.items():
        assert event.get("source") == "aws.cloudwatch" and event.get("detail-type") == _DETAIL_TYPE, (
            f"{op} event source/detail-type=({event.get('source')!r}, {event.get('detail-type')!r})"
        )
        assert event.get("resources") == [composite_arn], (
            f"{op} event resources={event.get('resources')!r}, expected exactly [{composite_arn!r}]"
        )
        assert event["detail"].get("alarmName") == composite, (
            f"{op} event detail.alarmName={event['detail'].get('alarmName')!r}"
        )
        conf = event["detail"].get("configuration") or {}
        assert conf.get("alarmRule") == expected_rule[op], (
            f"{op} event configuration.alarmRule={conf.get('alarmRule')!r}, expected "
            f"{expected_rule[op]!r}"
        )
        assert "metrics" not in conf, (
            f"{op} event for a COMPOSITE alarm carries configuration.metrics={conf.get('metrics')!r}; "
            f"a composite evaluates a rule, not a metric"
        )
        assert conf.get("actionsEnabled") is False, (
            f"{op} event configuration.actionsEnabled={conf.get('actionsEnabled')!r}, expected False"
        )
    prev = by_op["update"]["detail"].get("previousConfiguration") or {}
    assert prev.get("alarmRule") == good_rule, (
        f"update event previousConfiguration.alarmRule={prev.get('alarmRule')!r}, expected the "
        f"pre-update rule {good_rule!r}"
    )
    assert "previousConfiguration" not in by_op["create"]["detail"], (
        f"the composite's create event carries previousConfiguration="
        f"{by_op['create']['detail'].get('previousConfiguration')!r} — there was none, the earlier "
        f"write was rejected"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
