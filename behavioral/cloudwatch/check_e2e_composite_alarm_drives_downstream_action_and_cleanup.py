"""e2e-composite-alarm-drives-downstream-action-and-cleanup."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-composite-alarm-drives-downstream-action-and-cleanup"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Forcing both children of an AND composite alarm into ALARM drives the composite to ALARM and
    delivers its SNS notification to SQS; deleting composite then children leaves none listed."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cwcomp-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cwcomp-queue-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))

    child1 = ctx.unique_name("sim2real-cwcomp-child1-")
    child2 = ctx.unique_name("sim2real-cwcomp-child2-")
    composite = ctx.unique_name("sim2real-cwcomp-parent-")
    namespace = ctx.unique_name("Sim2Real/CompositeAlarm-")

    for child in (child1, child2):
        cw.put_metric_alarm(
            AlarmName=child,
            Namespace=namespace,
            MetricName="Latency",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
        )
    ctx.on_cleanup(lambda: _safe_call(lambda: cw.delete_alarms(AlarmNames=[child1, child2])))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f"ALARM({child1}) AND ALARM({child2})",
        AlarmActions=[topic_arn],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cw.delete_alarms(AlarmNames=[composite])))

    cw.set_alarm_state(AlarmName=child1, StateValue="ALARM", StateReason="sim2real behavioral check")
    cw.set_alarm_state(AlarmName=child2, StateValue="ALARM", StateReason="sim2real behavioral check")

    composite_state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])[
            "CompositeAlarms"
        ][0]["StateValue"],
        lambda state: state == "ALARM",
        timeout_s=90,
        interval_s=3,
    )
    assert composite_state == "ALARM", (
        f"expected composite alarm {composite!r} to reach ALARM, last observed state: {composite_state!r}"
    )

    messages = _wait_for_sqs_messages(sqs, queue_url, expected_count=1, timeout_s=60)
    assert len(messages) >= 1, (
        f"expected at least 1 SQS message delivered from the SNS action, got {len(messages)}"
    )
    envelope = json.loads(messages[0]["Body"])
    # SQS delivers the raw SNS envelope; the actual CloudWatch alarm state-change
    # notification is JSON-encoded inside the envelope's "Message" field.
    body = json.loads(envelope["Message"])
    assert body["AlarmName"] == composite, (
        f"expected notification AlarmName {composite!r}, got {body.get('AlarmName')!r}"
    )
    assert body["NewStateValue"] == "ALARM", (
        f"expected notification NewStateValue 'ALARM', got {body.get('NewStateValue')!r}"
    )
    for msg in messages:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    # Composite must be deleted before its children: while a child is still
    # referenced by a live composite's AlarmRule, DeleteAlarms on the child
    # raises ResourceConflict (see PutCompositeAlarm/DeleteAlarms docs).
    cw.delete_alarms(AlarmNames=[composite])
    cw.delete_alarms(AlarmNames=[child1, child2])

    remaining = cw.describe_alarms(AlarmNames=[composite, child1, child2])
    assert remaining["MetricAlarms"] == [], (
        f"expected no metric alarms to remain after delete, got {remaining['MetricAlarms']!r}"
    )
    assert remaining["CompositeAlarms"] == [], (
        f"expected no composite alarms to remain after delete, got {remaining['CompositeAlarms']!r}"
    )


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFound", "ResourceNotFound"):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed value: {last!r}")


def _wait_for_sqs_messages(sqs, queue_url, expected_count=1, timeout_s=60.0):
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        out.extend(resp.get("Messages", []))
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} in {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
