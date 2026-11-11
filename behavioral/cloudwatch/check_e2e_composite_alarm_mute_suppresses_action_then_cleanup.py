"""e2e-composite-alarm-mute-suppresses-action-then-cleanup."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-composite-alarm-mute-suppresses-action-then-cleanup"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A composite alarm's action is suppressed while an active mute rule targets it, and fires once unmuted."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-behav-child-")
    composite_name = ctx.unique_name("sim2real-behav-composite-")
    mute_rule_name = ctx.unique_name("sim2real-behav-mute-")
    namespace = ctx.unique_name("Sim2RealBehav/CompositeE2E-")
    metric_name = "ErrorRate"

    queue = _create_queue(ctx)
    topic = _create_topic(ctx)
    _subscribe_queue_to_topic(ctx, topic, queue)

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=10,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [child_name]))

    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        ActionsEnabled=True,
        AlarmActions=[topic["arn"]],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [composite_name]))

    # active mute window: started a couple minutes ago, lasts well beyond this test
    start = datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
    at_expr = f"at({start.strftime('%Y-%m-%dT%H:%M')})"
    cw.put_alarm_mute_rule(
        Name=mute_rule_name,
        Rule={"Schedule": {"Expression": at_expr, "Duration": "PT30M", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [composite_name]},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_mute_rule_ignore(cw, mute_rule_name))

    def _probe_mute_status() -> str:
        return cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)["Status"]

    mute_status = _poll_until(_probe_mute_status, lambda s: s == "ACTIVE", timeout_s=60.0, interval_s=1.0, ctx=ctx)
    if mute_status != "ACTIVE" and _budget_spent(ctx):
        raise TimeoutError("the mute rule to reach ACTIVE: the run budget ended first; not graded")
    assert mute_status == "ACTIVE", f"mute rule never reached ACTIVE, last status={mute_status}"

    def _send_breach() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 100.0,
                    "Unit": "Count",
                    "StorageResolution": 1,
                }
            ],
        )

    def _send_ok() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 0.0,
                    "Unit": "Count",
                    "StorageResolution": 1,
                }
            ],
        )

    def _probe_composite_state(feed) -> str:
        feed()  # keep feeding data points while we wait for evaluation to catch up
        alarms = cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
        return alarms[0]["StateValue"] if alarms else "MISSING"

    # drive the child alarm into ALARM with real breaching data -> composite should follow
    composite_state = _poll_until(
        lambda: _probe_composite_state(_send_breach), lambda s: s == "ALARM", timeout_s=90.0, interval_s=1.0, ctx=ctx
    )
    if composite_state != "ALARM" and _budget_spent(ctx):
        raise TimeoutError("the composite alarm to reach ALARM: the run budget ended first; not graded")
    assert composite_state == "ALARM", f"composite never reached ALARM, last state={composite_state}"

    # while muted, no notification should reach the queue despite the ALARM transition -- keep
    # feeding breaching data throughout the window to hold the alarm in ALARM
    leaked = _drain_messages(ctx, queue["url"], window_s=10.0, keep_alive=_send_breach)
    assert leaked == [], f"action fired while alarm was muted: {leaked}"

    sqs = ctx.client("sqs")
    depth = sqs.get_queue_attributes(
        QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
    )["Attributes"]
    assert depth["ApproximateNumberOfMessages"] == "0" and depth["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue depth non-zero after the muted drain window: {depth}"
    )

    # remove the mute rule and confirm it is gone
    cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)
    code = _error_code(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"

    # positive control: reset to OK with real non-breaching data, then re-breach now that the
    # mute is gone -> the action must fire this time
    reset_state = _poll_until(
        lambda: _probe_composite_state(_send_ok), lambda s: s == "OK", timeout_s=90.0, interval_s=1.0, ctx=ctx
    )
    if reset_state != "OK" and _budget_spent(ctx):
        raise TimeoutError("the composite alarm to reset to OK: the run budget ended first; not graded")
    assert reset_state == "OK", f"composite never reset to OK, last state={reset_state}"

    composite_state = _poll_until(
        lambda: _probe_composite_state(_send_breach), lambda s: s == "ALARM", timeout_s=90.0, interval_s=1.0, ctx=ctx
    )
    if composite_state != "ALARM" and _budget_spent(ctx):
        raise TimeoutError("the composite alarm to re-breach: the run budget ended first; not graded")
    assert composite_state == "ALARM", f"composite never re-breached, last state={composite_state}"

    messages = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=60.0)
    inner = json.loads(messages[0]["body"]["Message"])
    assert inner["AlarmName"] == composite_name, f"expected notification for {composite_name}, got {inner['AlarmName']}"
    assert inner["NewStateValue"] == "ALARM", f"expected NewStateValue ALARM, got {inner['NewStateValue']}"

    # final teardown: composite must be deleted before its child (a metric alarm still
    # referenced by an existing composite alarm's rule cannot be deleted directly)
    cw.delete_alarms(AlarmNames=[composite_name])
    cw.delete_alarms(AlarmNames=[child_name])
    after = cw.describe_alarms(AlarmNames=[composite_name, child_name], AlarmTypes=["MetricAlarm", "CompositeAlarm"])
    assert after["MetricAlarms"] == [] and after["CompositeAlarms"] == [], (
        f"expected both alarms gone after delete, still describable: {after}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


def _error_code(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_alarms_ignore(cw, names: list[str]) -> None:
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_mute_rule_ignore(cw, name: str) -> None:
    try:
        cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ResourceNotFoundException"):
            raise


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-compq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-comptopic-"), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _subscribe_queue_to_topic(ctx, topic: dict[str, str], queue: dict[str, str]) -> None:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(lambda arn=sub["SubscriptionArn"]: sns.unsubscribe(SubscriptionArn=arn))


def _drain_messages(ctx, queue_url: str, window_s: float, keep_alive=None) -> list[dict[str, Any]]:
    """Poll for the whole window and return whatever (if anything) showed up -- used to prove absence."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        if keep_alive is not None:
            keep_alive()
        wait = max(1, min(2, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            out.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _wait_for_messages(ctx, queue_url: str, expected_count: int = 1, timeout_s: float = 60.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            out.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        if _budget_spent(ctx):
            raise TimeoutError(f"{expected_count} SNS notification(s) on the queue: the run budget "
                               f"ended first; not graded")
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} within the wait bound")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
