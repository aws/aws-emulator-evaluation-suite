"""obs-s3-1-filter-alarm-notification-to-queue-without-sns-policy-blocked."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "obs-s3-1-filter-alarm-notification-to-queue-without-sns-policy-blocked"
GROUP = "alerting"
SERVICES = ["cloudwatch", "s3", "sns", "sqs"]

_FILTER_ID = "sim2realobsblocked"


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An S3-filter alarm's two ALARM notifications reach the queue whose policy admits SNS but not
    its twin without a policy, while the alarm's Action history records the publishes Succeeded;
    attaching the policy makes the same queue receive the next ALARM notification."""
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    bucket = ctx.unique_name("sim2real-obs-s3-blocked-")
    create_kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # transport-only fork
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: ctx.client("s3").delete_bucket(Bucket=bucket))
    s3.put_bucket_metrics_configuration(
        Bucket=bucket, Id=_FILTER_ID,
        MetricsConfiguration={"Id": _FILTER_ID, "Filter": {"Prefix": "blocked/"}},
    )
    ctx.on_cleanup(
        lambda: ctx.client("s3").delete_bucket_metrics_configuration(Bucket=bucket, Id=_FILTER_ID)
    )

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-obs-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))

    queues = {}
    for role in ("allowed", "blocked"):
        url = sqs.create_queue(
            QueueName=ctx.unique_name(f"sim2real-xsvc-obs-{role}-"),
            tags={"sim2real:managed": "true"},
        )["QueueUrl"]
        ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
            "Attributes"]["QueueArn"]
        queues[role] = {"url": url, "arn": arn}

    def _policy(queue_arn: str) -> str:
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }],
        })

    sqs.set_queue_attributes(
        QueueUrl=queues["allowed"]["url"], Attributes={"Policy": _policy(queues["allowed"]["arn"])}
    )
    blocked_attrs = sqs.get_queue_attributes(
        QueueUrl=queues["blocked"]["url"], AttributeNames=["Policy"]
    ).get("Attributes", {})
    assert "Policy" not in blocked_attrs, (
        f"the blocked queue already carries a policy {blocked_attrs!r}; the check needs it absent"
    )
    for role, q in queues.items():
        sub = sns.subscribe(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=q["arn"], ReturnSubscriptionArn=True
        )["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: ctx.client("sns").unsubscribe(SubscriptionArn=s))

    alarm = ctx.unique_name("sim2real-xsvc-obs-blocked-")
    cw.put_metric_alarm(
        AlarmName=alarm, Namespace="AWS/S3", MetricName="4xxErrors",
        Dimensions=[{"Name": "BucketName", "Value": bucket},
                    {"Name": "FilterId", "Value": _FILTER_ID}],
        Statistic="Sum", Period=60, EvaluationPeriods=1, Threshold=2.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold", ActionsEnabled=True,
        AlarmActions=[topic_arn], Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[alarm]))

    def _fire(reason: str) -> None:
        cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason=f"{reason}: reset")
        cw.set_alarm_state(AlarmName=alarm, StateValue="ALARM", StateReason=reason)

    def _drain(role: str, wait_s: int) -> list[dict]:
        resp = sqs.receive_message(
            QueueUrl=queues[role]["url"], MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
        )
        out = []
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            payload = json.loads(envelope["Message"])
            out.append(payload)
            sqs.delete_message(QueueUrl=queues[role]["url"], ReceiptHandle=msg["ReceiptHandle"])
        return out

    # ---- differential barrier: two ALARM notifications reach the allowed queue -------------- #
    allowed_got: list[dict] = []
    blocked_got: list[dict] = []
    for n in (1, 2):
        reason = f"sim2real barrier publish {n}"
        _fire(reason)
        deadline = time.monotonic() + 120
        while not any(p.get("NewStateReason") == reason for p in allowed_got):
            assert time.monotonic() < deadline, (
                f"the allowed queue (with the SNS policy) never received ALARM notification "
                f"{n} within 120s; got {allowed_got!r}. Without this barrier the absence below "
                f"proves nothing"
            )
            allowed_got.extend(_drain("allowed", 10))
            blocked_got.extend(_drain("blocked", 0))
    blocked_got.extend(_drain("blocked", 5))
    assert [p.get("AlarmName") for p in allowed_got] == [alarm, alarm], (
        f"the allowed queue received {allowed_got!r}, expected exactly two notifications for "
        f"{alarm!r}"
    )
    assert blocked_got == [], (
        f"the queue with NO policy received {len(blocked_got)} notification(s) {blocked_got!r} "
        f"while the allowed queue received two from the same publishes; SNS must not deliver to "
        f"an SQS queue whose policy does not grant sns.amazonaws.com sqs:SendMessage"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=queues["blocked"]["url"],
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert depth == {"ApproximateNumberOfMessages": "0",
                     "ApproximateNumberOfMessagesNotVisible": "0"}, (
        f"the blocked queue reports depth {depth!r}; nothing may have been enqueued"
    )

    # CloudWatch's side of the hop succeeded: the loss is downstream of the alarm.
    actions = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm, HistoryItemType="Action"
    ):
        actions.extend(json.loads(i["HistoryData"]) for i in page["AlarmHistoryItems"])
    states = [a.get("actionState") for a in actions]
    assert states.count("Succeeded") >= 2 and "Failed" not in states, (
        f"alarm Action history states {states!r}; both publishes to the topic must have "
        f"Succeeded -- the block is at SNS -> SQS, not CloudWatch -> SNS"
    )

    # ---- repair the ONE broken thing; the same queue must now receive ---------------------- #
    sqs.set_queue_attributes(
        QueueUrl=queues["blocked"]["url"], Attributes={"Policy": _policy(queues["blocked"]["arn"])}
    )
    deadline = time.monotonic() + 240
    attempt = 0
    repaired: list[dict] = []
    while not repaired:
        assert time.monotonic() < deadline, (
            f"after attaching the SNS policy to the previously blocked queue, no notification "
            f"arrived within 240s over {attempt} publishes; the queue was never reachable, so "
            f"the earlier absence was not caused by the missing policy"
        )
        attempt += 1
        _fire(f"sim2real repair publish {attempt}")
        repaired = [p for p in _drain("blocked", 20) if p.get("AlarmName") == alarm]
    assert repaired[0]["NewStateValue"] == "ALARM", (
        f"repaired-queue notification {repaired[0]!r} is not an ALARM transition"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
