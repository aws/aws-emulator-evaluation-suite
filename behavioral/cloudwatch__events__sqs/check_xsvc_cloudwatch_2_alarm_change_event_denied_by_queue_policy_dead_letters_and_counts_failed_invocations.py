"""xsvc-cloudwatch-2-alarm-change-event-denied-by-queue-policy-dead-letters-and-counts-failed-invocations."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = (
    "xsvc-cloudwatch-2-alarm-change-event-denied-by-queue-policy-dead-letters-and-counts-failed-invocations"
)
GROUP = "error-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_DETAIL_TYPE = "CloudWatch Alarm Configuration Change"
_NAMESPACE = "Sim2Real/XsvcCw2"
_METRIC = "DlqProbe"


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


def _set_policy(ctx, url, queue_arn, effect, rule_arn):
    stmt = {
        "Sid": f"{effect}Events",
        "Effect": effect,
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
        "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=url,
        Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})},
    )


def _put_rule(ctx, name, alarm, check_tag):
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"alarmName": [alarm]},
    }
    arn = ctx.client("events").put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, name))
    return arn


def _put_targets_ok(ctx, rule, targets):
    resp = ctx.client("events").put_targets(Rule=rule, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, name):
    events = ctx.client("events")
    events.remove_targets(Rule=name, Ids=["t"], Force=True)
    events.delete_rule(Name=name, Force=True)


def _drain(ctx, url, *, seconds):
    """Receive and delete for up to `seconds`; returns raw messages (attributes included).
    `.get("Messages", [])` feeds a list asserted by exact value — the sanctioned polarity."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _rule_metric(ctx, metric, rule, since):
    """Default-bus rules publish AWS/Events metrics under the single dimension RuleName (measured:
    the EventBusName+RuleName pair carries no datapoint for a default-bus rule)."""
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": "RuleName", "Value": rule}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(p["Sum"] for p in resp.get("Datapoints", []))  # polarity: feeds asserted sums


def _put_alarm(cw, name, threshold):
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=_NAMESPACE,
        MetricName=_METRIC,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=float(threshold),
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        TreatMissingData="missing",
    )


def _attr(msg, key):
    return msg.get("MessageAttributes", {}).get(key, {}).get("StringValue")


# ===== the check =====
# timing:real-time — metric: 51 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:negative-delivery",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """An alarm change event whose target queue policy denies EventBridge is dead-lettered with
    ERROR_CODE=NO_RESOURCE naming that rule and target and counted as failed for that rule only;
    restoring the policy restores delivery."""
    cw = ctx.client("cloudwatch")
    check_tag = "xsvc-cloudwatch-2-dlq-denied"
    suffix = uuid.uuid4().hex[:10]
    alarm = ctx.unique_name("sim2real-xsvc-cw2-dlq-al-")
    bad_rule = ctx.unique_name("sim2real-xsvc-cw2-bad-")
    good_rule = ctx.unique_name("sim2real-xsvc-cw2-good-")

    target_url, target_arn = _make_queue(ctx, f"sim2real-xsvc-cw2-tgt-{suffix}", check_tag)
    dlq_url, dlq_arn = _make_queue(ctx, f"sim2real-xsvc-cw2-dlq-{suffix}", check_tag)
    good_url, good_arn = _make_queue(ctx, f"sim2real-xsvc-cw2-ok-{suffix}", check_tag)

    bad_rule_arn = _put_rule(ctx, bad_rule, alarm, check_tag)
    good_rule_arn = _put_rule(ctx, good_rule, alarm, check_tag)
    # THE BREAK: the target queue explicitly denies EventBridge for the failing rule.
    _set_policy(ctx, target_url, target_arn, "Deny", bad_rule_arn)
    _set_policy(ctx, dlq_url, dlq_arn, "Allow", bad_rule_arn)
    _set_policy(ctx, good_url, good_arn, "Allow", good_rule_arn)
    _put_targets_ok(
        ctx,
        bad_rule,
        [
            {
                "Id": "t",
                "Arn": target_arn,
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
                "DeadLetterConfig": {"Arn": dlq_arn},
            }
        ],
    )
    _put_targets_ok(ctx, good_rule, [{"Id": "t", "Arn": good_arn}])

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))

    # Each PutMetricAlarm emits one event to BOTH rules at the same instant (a differential barrier).
    # Re-put with a fresh threshold until the healthy rule AND the DLQ have each received one, since
    # resource-policy propagation exposes no condition to poll other than delivery itself.
    good_seen, dead_seen = [], []
    attempt = {"n": 0}

    def _trigger_and_collect():
        attempt["n"] += 1
        _put_alarm(cw, alarm, attempt["n"])
        good_seen.extend(_drain(ctx, good_url, seconds=5))
        dead_seen.extend(_drain(ctx, dlq_url, seconds=5))
        return len(good_seen), len(dead_seen)

    t0 = time.monotonic()
    _poll_until(
        _trigger_and_collect,
        lambda counts: counts[0] >= 1 and counts[1] >= 1,
        timeout_s=150,
        interval_s=0,
        description=(
            f"one alarm change event reached the healthy rule's queue AND the failing rule's DLQ "
            f"(good, dlq counts)"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    triggers = attempt["n"]

    good_ids = set()
    for m in good_seen:
        body = json.loads(m["Body"])
        assert body.get("source") == "aws.cloudwatch" and body["detail"].get("alarmName") == alarm, (
            f"the healthy queue received a foreign event: {m['Body'][:200]!r}"
        )
        good_ids.add(body["id"])

    alarm_arn = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["AlarmArn"]
    for m in dead_seen:
        assert _attr(m, "ERROR_CODE") == "NO_RESOURCE", (
            f"the DLQ copy carries ERROR_CODE={_attr(m, 'ERROR_CODE')!r}, expected 'NO_RESOURCE' for an "
            f"SQS target whose policy denies events.amazonaws.com (ERROR_MESSAGE="
            f"{_attr(m, 'ERROR_MESSAGE')!r})"
        )
        assert _attr(m, "RULE_ARN") == bad_rule_arn, (
            f"the DLQ copy names RULE_ARN={_attr(m, 'RULE_ARN')!r}, expected the failing rule "
            f"{bad_rule_arn!r} (the healthy rule is {good_rule_arn!r})"
        )
        assert _attr(m, "TARGET_ARN") == target_arn, (
            f"the DLQ copy names TARGET_ARN={_attr(m, 'TARGET_ARN')!r}, expected {target_arn!r}"
        )
        body = json.loads(m["Body"])
        assert (body.get("source"), body.get("detail-type")) == ("aws.cloudwatch", _DETAIL_TYPE), (
            f"the dead-lettered body is not the alarm change event: {m['Body'][:200]!r}"
        )
        assert body.get("resources") == [alarm_arn] and body["detail"].get("alarmName") == alarm, (
            f"the dead-lettered event names resources={body.get('resources')!r} "
            f"alarmName={body['detail'].get('alarmName')!r}, expected [{alarm_arn!r}] / {alarm!r}"
        )
    # Envelope identity: the first dead-lettered event is one the healthy twin ALSO received, i.e. the
    # DLQ holds the original event, not a synthesised one. (Later triggers may still be in flight.)
    _poll_until(
        lambda: good_ids.update(
            json.loads(m["Body"])["id"] for m in _drain(ctx, good_url, seconds=4)
        ) or good_ids,
        lambda ids: json.loads(dead_seen[0]["Body"])["id"] in ids,
        timeout_s=60,
        interval_s=0,
        description=(
            f"the dead-lettered event id {json.loads(dead_seen[0]['Body'])['id']!r} was also delivered "
            f"to the healthy rule"
        ),
    )

    # THE ABSENCE: nothing reached the denied target, by receive and by depth.
    leaked = _drain(ctx, target_url, seconds=max(2 * latency, 10.0))
    assert leaked == [], (
        f"the target queue whose policy DENIES EventBridge received {len(leaked)} message(s): "
        f"{[m['Body'][:120] for m in leaked]!r}"
    )
    assert _queue_depth(ctx, target_url) == 0, (
        f"the denied target reports depth {_queue_depth(ctx, target_url)} behind an empty receive"
    )

    # TELEMETRY: FailedInvocations for the failing rule, and none for the healthy sibling.
    failed_bad = _poll_until(
        lambda: _rule_metric(ctx, "FailedInvocations", bad_rule, window_start),
        lambda total: total >= 1,
        timeout_s=240,
        interval_s=15,
        description=f"AWS/Events FailedInvocations (RuleName={bad_rule}) recorded the denied delivery",
    )
    assert failed_bad <= triggers, (
        f"FailedInvocations Sum={failed_bad} for {bad_rule} exceeds the {triggers} events this check "
        f"caused — retries are disabled (MaximumRetryAttempts=0)"
    )
    sent_to_dlq = _rule_metric(ctx, "InvocationsSentToDlq", bad_rule, window_start)
    assert sent_to_dlq >= 1, (
        f"InvocationsSentToDlq Sum={sent_to_dlq} for {bad_rule}, expected >=1 — the DLQ demonstrably "
        f"holds {len(dead_seen)} dead-lettered event(s)"
    )
    ok_success = _poll_until(
        lambda: _rule_metric(ctx, "SuccessfulInvocationAttempts", good_rule, window_start),
        lambda total: total >= 1,
        timeout_s=120,
        interval_s=15,
        description=f"SuccessfulInvocationAttempts (RuleName={good_rule}) recorded the healthy delivery",
    )
    assert ok_success >= 1, f"SuccessfulInvocationAttempts Sum={ok_success} for {good_rule}"
    failed_good = _rule_metric(ctx, "FailedInvocations", good_rule, window_start)
    assert failed_good == 0, (
        f"the healthy rule {good_rule} recorded FailedInvocations Sum={failed_good}, expected 0 — "
        f"its target accepted every delivery, so the failure must be attributed to {bad_rule} only"
    )

    # REPAIR the one broken thing and demand delivery to the SAME target.
    _set_policy(ctx, target_url, target_arn, "Allow", bad_rule_arn)
    delivered = []

    def _retrigger():
        attempt["n"] += 1
        _put_alarm(cw, alarm, attempt["n"])
        delivered.extend(_drain(ctx, target_url, seconds=8))
        return delivered

    _poll_until(
        _retrigger,
        lambda msgs: len(msgs) >= 1,
        timeout_s=180,
        interval_s=0,
        description=f"with the Deny replaced by an Allow, the rule {bad_rule} delivered to {target_url}",
    )
    body = json.loads(delivered[0]["Body"])
    assert body["detail"].get("alarmName") == alarm and body["detail"].get("operation") == "update", (
        f"the repaired target received alarmName={body['detail'].get('alarmName')!r} "
        f"operation={body['detail'].get('operation')!r}, expected {alarm!r} / 'update'"
    )
    assert body.get("resources") == [alarm_arn], (
        f"the repaired delivery names resources={body.get('resources')!r}, expected [{alarm_arn!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
