"""cloudfront-4xx-alarm-cross-region-sns-action-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cloudfront-4xx-alarm-cross-region-sns-action-rejected"
GROUP = "alerting"
SERVICES = ["cloudfront", "cloudwatch", "sns", "sqs"]

#: CloudFront publishes distribution metrics to CloudWatch in us-east-1 only, so an alarm on
#: AWS/CloudFront has to live there. This literal is the documented home of a global resource's
#: telemetry, not this account's region.
METRIC_REGION = "us-east-1"
#: A real region that is NOT the alarm's region, for the cross-region topic. Any region other than
#: METRIC_REGION would do; the assertion derives its expected message from this constant.
OTHER_REGION = "us-west-2"

_XSVC_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _error(fn):
    """Return (code, message) of the ClientError fn raises; RAISE if it unexpectedly succeeds."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - only botocore ClientError carries .response
        err = getattr(exc, "response", {}).get("Error") if hasattr(exc, "response") else None
        if not err:
            raise
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call was ACCEPTED but real AWS rejects it")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _topic_to_queue(ctx, sns, sqs) -> tuple[str, str]:
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-cfxr-"),
        Tags=[{"Key": k, "Value": v} for k, v in _XSVC_TAGS.items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-cfxr-"),
                                 tags=_XSVC_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            Attributes={"RawMessageDelivery": "true"},
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return topic_arn, queue_url


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "cap:c1",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS/CloudFront alarm in us-east-1 refuses a foreign-region SNS action on create and update.

    The refused update leaves the co-regional action in place, and it still delivers to SQS.
    """
    cw = ctx.client("cloudwatch", region=METRIC_REGION)
    sns = ctx.client("sns", region=METRIC_REGION)
    sqs = ctx.client("sqs", region=METRIC_REGION)
    sns_other = ctx.client("sns", region=OTHER_REGION)
    # The foreign topic is real, so the refusal is about region, not a nonexistent ARN.

    foreign_topic = sns_other.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-cfxr-foreign-"),
        Tags=[{"Key": k, "Value": v} for k, v in _XSVC_TAGS.items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns_other.delete_topic(TopicArn=foreign_topic))
    assert f":sns:{OTHER_REGION}:" in foreign_topic, f"unexpected foreign topic ARN {foreign_topic!r}"

    local_topic, queue_url = _topic_to_queue(ctx, sns, sqs)

    name = ctx.unique_name("sim2real-xsvc-cfxr-alarm-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    alarm = dict(
        AlarmName=name,
        Namespace="AWS/CloudFront",
        MetricName="4xxErrorRate",
        # A well-formed but fabricated id: PutMetricAlarm never resolves dimension values.
        Dimensions=[{"Name": "DistributionId", "Value": "E0SIM2REALXSVC"},
                    {"Name": "Region", "Value": "Global"}],
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=20.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": k, "Value": v} for k, v in _XSVC_TAGS.items()],
    )
    expected_msg = f"Invalid region {OTHER_REGION} specified. Only {METRIC_REGION} is supported."

    # 1. create with the foreign action: refused, and nothing was created.
    code, msg = _error(lambda: cw.put_metric_alarm(AlarmActions=[foreign_topic], **alarm))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}: {msg!r}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    absent = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert absent == [], f"a refused PutMetricAlarm still created the alarm: {absent!r}"

    # 2. positive control: the same alarm with the co-regional action is accepted.
    cw.put_metric_alarm(AlarmActions=[local_topic], **alarm)
    created = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert len(created) == 1 and created[0]["AlarmActions"] == [local_topic], (
        f"expected one alarm whose only action is {local_topic!r}, got {created!r}"
    )

    # 3. update adding the foreign action beside the good one: refused, and state unchanged.
    code, msg = _error(lambda: cw.put_metric_alarm(AlarmActions=[local_topic, foreign_topic],
                                                   **alarm))
    assert code == "ValidationError", f"expected ValidationError on update, got {code!r}: {msg!r}"
    assert msg == expected_msg, f"expected message {expected_msg!r} on update, got {msg!r}"
    after = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert len(after) == 1 and after[0]["AlarmActions"] == [local_topic], (
        f"a refused update changed the alarm's actions: {after!r}"
    )

    # 4. the surviving action still delivers a real notification, end to end.
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM",
                       StateReason="sim2real: prove the co-regional action survived")
    received: list[dict] = []

    def drain():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            received.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        return [m for m in received if m.get("AlarmName") == name]

    hits = _poll_until(drain, bool, timeout_s=120.0, interval_s=1.0,
                       description=f"the ALARM notification for {name} in SQS")
    assert hits[0].get("NewStateValue") == "ALARM", (
        f"notification NewStateValue={hits[0].get('NewStateValue')!r}, expected ALARM"
    )
    assert (hits[0].get("Trigger") or {}).get("Namespace") == "AWS/CloudFront", (
        f"notification Trigger={hits[0].get('Trigger')!r} does not name AWS/CloudFront"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
