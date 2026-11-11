"""rds-alarm-action-blocked-by-topic-policy-denying-cloudwatch."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-alarm-action-blocked-by-topic-policy-denying-cloudwatch"
GROUP = "permissions"
SERVICES = ["cloudwatch", "rds"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
    {"Key": "sim2real", "Value": "rds-alarm-action-blocked"},
]
#: Ceilings, never sleeps: `_poll_until` RAISES when one is exceeded.
_ALARM_BUDGET_S = 600
_DELIVERY_BUDGET_S = 300
#: Bounded re-arms of the repair alarm: an SNS policy edit is eventually consistent, and a repair
#: alarm that fires before the edit is enforced records Failed once and never retries.
_REPAIR_ATTEMPTS = 4


def _poll_until(probe, pred, *, timeout_s, interval_s, description):
    """Poll probe() until pred(value); RAISE on the deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)


def _instance_absent(rds, inst_id):
    try:
        rds.describe_db_instances(DBInstanceIdentifier=inst_id)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound"
    return False


def _action_items(cw, name):
    """Every Action history item for one alarm, HistoryData parsed."""
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="Action", AlarmTypes=["MetricAlarm"]
    ):
        for item in page.get("AlarmHistoryItems", []):
            items.append(json.loads(item["HistoryData"]))
    return items


def _by_resource(items):
    return {i.get("notificationResource"): i for i in items}


def _drain(sqs, queue_url, inbox):
    """Receive every currently visible message, parse the SNS envelope, delete it, append."""
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
    for msg in resp.get("Messages", []):
        inbox.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return inbox


def _notes(inbox, topic_arn, alarm_name):
    out = []
    for env in inbox:
        if env.get("TopicArn") != topic_arn:
            continue
        try:
            body = json.loads(env.get("Message", ""))
        except (TypeError, ValueError):
            continue
        if isinstance(body, dict) and body.get("AlarmName") == alarm_name:
            out.append(body)
    return out


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "cap:c7",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An alarm action to an SNS topic denying cloudwatch.amazonaws.com sns:Publish fails and delivers
    nothing, while a sibling default-policy topic delivers; removing the Deny restores delivery.
    """
    rds = ctx.client("rds")
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    # The alarm transitions for real: TreatMissingData=breaching on an instance that does not exist.
    ghost_id = ctx.unique_name("sim2real-xsvc-nosuch-")
    assert _instance_absent(rds, ghost_id), (
        f"the alarm's dimension must name no RDS instance, but {ghost_id!r} exists"
    )

    allowed = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-allow-"), Tags=_TAGS)[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=allowed))
    denied = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-deny-"), Tags=_TAGS)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=denied))

    default_policy = sns.get_topic_attributes(TopicArn=denied)["Attributes"]["Policy"]
    deny_policy = json.loads(default_policy)
    deny_policy["Statement"].append(
        {
            "Sid": "DenyCloudWatchPublish",
            "Effect": "Deny",
            "Principal": {"Service": "cloudwatch.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": denied,
        }
    )
    sns.set_topic_attributes(
        TopicArn=denied, AttributeName="Policy", AttributeValue=json.dumps(deny_policy)
    )
    stored = json.loads(sns.get_topic_attributes(TopicArn=denied)["Attributes"]["Policy"])
    assert any(s.get("Sid") == "DenyCloudWatchPublish" for s in stored.get("Statement", [])), (
        f"the Deny statement must be stored on {denied}; policy is {stored!r}"
    )

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": [allowed, denied]}},
                        }
                    ],
                }
            )
        },
    )
    for topic in (allowed, denied):
        sub = sns.subscribe(
            TopicArn=topic, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
        )["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: sns.unsubscribe(SubscriptionArn=s))
        assert sub.startswith(topic + ":"), f"subscription to {topic} not confirmed: {sub!r}"

    def _put_alarm(name, actions):
        cw.put_metric_alarm(
            AlarmName=name,
            AlarmDescription="sim2real rds alarm-action authorization negative",
            Namespace="AWS/RDS",
            MetricName="DatabaseConnections",
            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": ghost_id}],
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            TreatMissingData="breaching",
            AlarmActions=actions,
            Tags=_TAGS,
        )

    alarm = ctx.unique_name("sim2real-xsvc-alarm-")
    _put_alarm(alarm, [allowed, denied])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    # One alarm, both topics, one evaluation: the allowed topic's delivery is the barrier.
    acts = _poll_until(
        lambda: _by_resource(_action_items(cw, alarm)),
        lambda by: allowed in by and denied in by,
        timeout_s=_ALARM_BUDGET_S,
        interval_s=15,
        description=f"Action history items for both topics on alarm {alarm}",
    )
    assert acts[allowed].get("actionState") == "Succeeded", (
        f"the positive control action to {allowed} must succeed; got {acts[allowed]!r}"
    )
    inbox = []
    good = _poll_until(
        lambda: _notes(_drain(sqs, queue_url, inbox), allowed, alarm),
        lambda found: any(b.get("NewStateValue") == "ALARM" for b in found),
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=5,
        description=f"the allowed topic's ALARM notification for {alarm} in the queue",
    )
    assert good[0].get("Trigger", {}).get("Namespace") == "AWS/RDS", (
        f"the delivered notification must be the AWS/RDS alarm; got {good[0]!r}"
    )

    blocked = acts[denied]
    assert blocked.get("actionState") == "Failed", (
        f"an alarm action to a topic denying cloudwatch.amazonaws.com sns:Publish must FAIL; got "
        f"{blocked!r}"
    )
    error = blocked.get("error") or ""
    assert "not authorized to perform: SNS:Publish" in error and denied in error, (
        f"the failed action must name the SNS:Publish authorization on {denied}; got {error!r}"
    )
    assert blocked.get("publishedMessage") is None, (
        f"a refused action must hand SNS no message; got {blocked.get('publishedMessage')!r}"
    )
    for _ in range(3):
        _drain(sqs, queue_url, inbox)
    leaked = _notes(inbox, denied, alarm)
    assert leaked == [], (
        f"the denied topic must deliver nothing; queue received {len(leaked)} notification(s) "
        f"for {alarm} from {denied}: {leaked[:1]!r}"
    )

    # Removing the Deny proves the path was reachable and the Deny alone suppressed delivery.
    sns.set_topic_attributes(TopicArn=denied, AttributeName="Policy", AttributeValue=default_policy)
    repaired = None
    attempts = []
    for attempt in range(_REPAIR_ATTEMPTS):
        repair = ctx.unique_name("sim2real-xsvc-repair-")
        _put_alarm(repair, [denied])
        ctx.on_cleanup(lambda r=repair: cw.delete_alarms(AlarmNames=[r]))
        item = _poll_until(
            lambda: _by_resource(_action_items(cw, repair)).get(denied),
            lambda i: i is not None,
            timeout_s=_ALARM_BUDGET_S,
            interval_s=15,
            description=f"repair alarm {repair} (attempt {attempt + 1}) executing its action",
        )
        attempts.append(item.get("actionState"))
        if item.get("actionState") == "Succeeded":
            repaired = repair
            break
    assert repaired is not None, (
        f"after removing the Deny, an alarm action to {denied} must succeed; "
        f"{_REPAIR_ATTEMPTS} attempts recorded {attempts!r}"
    )
    delivered = _poll_until(
        lambda: _notes(_drain(sqs, queue_url, inbox), denied, repaired),
        lambda found: any(b.get("NewStateValue") == "ALARM" for b in found),
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=5,
        description=f"the repaired topic's notification for {repaired} in the same queue",
    )
    assert delivered[0].get("AlarmName") == repaired, f"unexpected notification {delivered[0]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
