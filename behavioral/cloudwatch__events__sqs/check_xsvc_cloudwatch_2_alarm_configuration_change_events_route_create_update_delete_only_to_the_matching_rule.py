"""xsvc-cloudwatch-2-alarm-configuration-change-events-route-create-update-delete-only-to-the-matching-rule."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = (
    "xsvc-cloudwatch-2-alarm-configuration-change-events-route-create-update-delete-only-to-the-matching-rule"
)
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_DETAIL_TYPE = "CloudWatch Alarm Configuration Change"
_NAMESPACE = "Sim2Real/XsvcCw2"
_METRIC = "ConfigChangeProbe"


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


def _allow_rule(ctx, url, queue_arn, rule_arn):
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=url,
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
    _allow_rule(ctx, queue_url, queue_arn, rule_arn)
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


def _put_alarm(cw, name, threshold, *, actions_enabled, alarm_actions):
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=_NAMESPACE,
        MetricName=_METRIC,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=float(threshold),
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=actions_enabled,
        AlarmActions=alarm_actions,
        TreatMissingData="missing",
    )


def _metric_of(configuration):
    metrics = configuration.get("metrics") or []
    assert len(metrics) == 1, (
        f"the event configuration carries {len(metrics)} metric entries, expected exactly 1 for a "
        f"single-metric alarm: {configuration!r}"
    )
    stat = metrics[0].get("metricStat", {})
    return stat.get("metric", {}).get("namespace"), stat.get("metric", {}).get("name"), stat


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
@tags("axis:happy-path", "concern:eventing", "concern:e2e", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Creating, updating and deleting an alarm each emit one configuration-change event, in order,
    that reaches only the rule scoped to that alarm's name and carries the configuration then in
    force (previousConfiguration on update only); the decoy rule receives none of them."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = "xsvc-cloudwatch-2-config-change-route"
    suffix = uuid.uuid4().hex[:10]

    alarm = ctx.unique_name("sim2real-xsvc-cw2-al-")
    warm = ctx.unique_name("sim2real-xsvc-cw2-warm-")
    decoy = ctx.unique_name("sim2real-xsvc-cw2-decoy-")
    # An action ARN is only an address to CloudWatch until the alarm enters ALARM, which this alarm
    # never does (no datapoints). Real AWS accepts a well-formed SNS ARN with no topic behind it; it
    # is built from the caller's own account, so nothing pre-existing is referenced.
    action_arn = f"arn:aws:sns:{ctx.region}:{account}:sim2real-xsvc-cw2-noop-{suffix}"

    main_url, main_arn = _make_queue(ctx, f"sim2real-xsvc-cw2-main-{suffix}", check_tag)
    decoy_url, decoy_arn = _make_queue(ctx, f"sim2real-xsvc-cw2-decoy-{suffix}", check_tag)

    _make_rule(
        ctx, ctx.unique_name("sim2real-xsvc-cw2-main-"), [alarm, warm], main_url, main_arn, check_tag
    )
    _make_rule(
        ctx, ctx.unique_name("sim2real-xsvc-cw2-decoy-"), [decoy], decoy_url, decoy_arn, check_tag
    )

    # Warm-up: neither the new rule nor the queue policy has an "effective now" signal, so the barrier
    # is an observable one — re-put a SEPARATE warm-up alarm (the main rule also matches its name)
    # until five consecutive writes each delivered their own event. The alarm under test is not
    # touched until the path is proven live.
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[warm]))
    _prove_path_live(
        ctx, main_url, warm,
        lambda n: _put_alarm(cw, warm, n, actions_enabled=False, alarm_actions=[]),
    )
    cw.delete_alarms(AlarmNames=[warm])
    _drain(ctx, main_url, seconds=4)  # discard any trailing warm-up events; filtered below anyway

    # 1. create
    t0 = time.monotonic()
    _put_alarm(cw, alarm, 5, actions_enabled=True, alarm_actions=[action_arn])
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))
    described = cw.describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(described) == 1, f"DescribeAlarms returned {len(described)} alarms for {alarm!r}"
    alarm_arn = described[0]["AlarmArn"]
    assert alarm_arn == f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{alarm}", (
        f"DescribeAlarms AlarmArn is {alarm_arn!r}, not the alarm ARN of {alarm!r}"
    )

    collected = []

    def _await_op(op):
        """Drain until this alarm's `op` event has arrived; every non-warm-up event is kept."""

        def _probe():
            collected.extend(
                m for m in _drain(ctx, main_url, seconds=4)
                if m.get("detail", {}).get("alarmName") != warm
            )
            return [m.get("detail", {}).get("operation") for m in collected]

        _poll_until(
            _probe,
            lambda ops_so_far: op in ops_so_far,
            timeout_s=90,
            interval_s=0,
            description=f"the rule scoped to {alarm} received the {op!r} event (operations so far)",
        )

    # Each write waits for its own event before the next one, so the three are attributable one by
    # one (a DeleteAlarms issued milliseconds after an update can produce no delete event within
    # 120 s, while the stepped form delivers every one).
    _await_op("create")
    latency = max(time.monotonic() - t0, 1.0)
    # 2. update: a new threshold AND actions disabled, so `previousConfiguration` is distinguishable
    _put_alarm(cw, alarm, 9, actions_enabled=False, alarm_actions=[action_arn])
    _await_op("update")
    # 3. delete
    cw.delete_alarms(AlarmNames=[alarm])
    _await_op("delete")
    collected.extend(  # one more pass: a 4th event would be a duplicate or a misroute
        m for m in _drain(ctx, main_url, seconds=max(2 * latency, 6.0))
        if m.get("detail", {}).get("alarmName") != warm
    )
    collected = _unique_by_id(collected)
    seq = [m["detail"]["operation"] for m in collected]
    assert seq == ["create", "update", "delete"], (
        f"the matching rule received operations {seq!r} in that order, expected exactly "
        f"['create', 'update', 'delete'] for {alarm!r} (each write waited for its own event)"
    )
    ops = sorted(m["detail"]["operation"] for m in collected)
    assert ops == ["create", "delete", "update"], (
        f"the matching rule received operations {ops!r}, expected exactly one each of "
        f"create/update/delete for {alarm!r}"
    )
    by_op = {m["detail"]["operation"]: m for m in collected}

    for op, event in by_op.items():
        assert event.get("source") == "aws.cloudwatch", f"{op} event source={event.get('source')!r}"
        assert event.get("detail-type") == _DETAIL_TYPE, (
            f"{op} event detail-type={event.get('detail-type')!r}, expected {_DETAIL_TYPE!r}"
        )
        assert event.get("resources") == [alarm_arn], (
            f"{op} event resources={event.get('resources')!r}, expected exactly [{alarm_arn!r}]"
        )
        assert event["detail"].get("alarmName") == alarm, (
            f"{op} event detail.alarmName={event['detail'].get('alarmName')!r}, expected {alarm!r}"
        )
        assert event.get("account") == account and event.get("region") == ctx.region, (
            f"{op} event account/region=({event.get('account')!r}, {event.get('region')!r}), "
            f"expected ({account!r}, {ctx.region!r})"
        )
        conf = event["detail"].get("configuration") or {}
        ns, name, stat = _metric_of(conf)
        assert (ns, name) == (_NAMESPACE, _METRIC), (
            f"{op} event configuration.metrics names ({ns!r}, {name!r}), expected "
            f"({_NAMESPACE!r}, {_METRIC!r})"
        )
        assert (stat.get("period"), stat.get("stat")) == (60, "Average"), (
            f"{op} event metricStat period/stat=({stat.get('period')!r}, {stat.get('stat')!r}), "
            f"expected (60, 'Average')"
        )
        assert conf.get("alarmActions") == [action_arn], (
            f"{op} event configuration.alarmActions={conf.get('alarmActions')!r}, expected "
            f"[{action_arn!r}]"
        )
        assert conf.get("comparisonOperator") == "GreaterThanThreshold", (
            f"{op} event comparisonOperator={conf.get('comparisonOperator')!r}"
        )

    create_conf = by_op["create"]["detail"]["configuration"]
    assert (create_conf.get("threshold"), create_conf.get("actionsEnabled")) == (5.0, True), (
        f"create event threshold/actionsEnabled=({create_conf.get('threshold')!r}, "
        f"{create_conf.get('actionsEnabled')!r}), expected (5.0, True)"
    )
    assert "previousConfiguration" not in by_op["create"]["detail"], (
        f"the create event carries a previousConfiguration "
        f"{by_op['create']['detail'].get('previousConfiguration')!r} — a new alarm has none"
    )

    upd = by_op["update"]["detail"]
    assert (upd["configuration"].get("threshold"), upd["configuration"].get("actionsEnabled")) == (
        9.0,
        False,
    ), (
        f"update event configuration threshold/actionsEnabled=({upd['configuration'].get('threshold')!r}, "
        f"{upd['configuration'].get('actionsEnabled')!r}), expected the NEW values (9.0, False)"
    )
    prev = upd.get("previousConfiguration") or {}
    assert (prev.get("threshold"), prev.get("actionsEnabled")) == (5.0, True), (
        f"update event previousConfiguration threshold/actionsEnabled=({prev.get('threshold')!r}, "
        f"{prev.get('actionsEnabled')!r}), expected the PRE-update values (5.0, True)"
    )

    dele = by_op["delete"]["detail"]["configuration"]
    assert (dele.get("threshold"), dele.get("actionsEnabled")) == (9.0, False), (
        f"delete event configuration threshold/actionsEnabled=({dele.get('threshold')!r}, "
        f"{dele.get('actionsEnabled')!r}), expected the last-in-force values (9.0, False)"
    )

    # THE NEGATIVE CONTROL. The decoy rule matches a different alarm name; it must have received
    # nothing. Then the decoy's own alarm is created and its create event must arrive at the decoy
    # queue: that arrival is the barrier (any misrouted event of `alarm` was published earlier on the
    # same path) and the proof the decoy wiring was live all along.
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[decoy]))
    decoy_seen = []
    d_attempt = {"n": 0}

    def _decoy_probe():
        d_attempt["n"] += 1
        _put_alarm(cw, decoy, 100 + d_attempt["n"], actions_enabled=False, alarm_actions=[])
        decoy_seen.extend(_drain(ctx, decoy_url, seconds=max(latency, 6.0)))
        return decoy_seen

    _poll_until(
        _decoy_probe,
        lambda msgs: any(m.get("detail", {}).get("alarmName") == decoy for m in msgs),
        timeout_s=120,
        interval_s=0,
        description=f"the decoy rule's own alarm {decoy} delivered an event to {decoy_url}",
    )
    foreign = sorted(
        {m.get("detail", {}).get("alarmName") for m in decoy_seen} - {decoy}, key=str
    )
    assert foreign == [], (
        f"the decoy rule (scoped to {decoy!r}) received events for {foreign!r} — expected NONE for "
        f"{alarm!r}; a configuration-change rule must match on detail.alarmName, not broadcast"
    )
    assert decoy_seen[0].get("resources") == [
        f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{decoy}"
    ], f"the decoy event names resources={decoy_seen[0].get('resources')!r}"
    late = [m for m in _drain(ctx, main_url, seconds=4) if m["detail"].get("alarmName") == alarm]
    assert late == [], (
        f"the main rule received {len(late)} further event(s) for {alarm!r} after the barrier: "
        f"{[m['detail'].get('operation') for m in late]!r} — expected exactly three in total"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
