"""eventbridge-sns-target-missing-topic-policy-not-published."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-sns-target-missing-topic-policy-not-published"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SNS target without a topic-policy grant for events.amazonaws.com receives nothing from
    a matching rule, while a direct publish reaches the subscriber; granting the statement lets
    the same rule deliver."""
    topic_arn = _create_topic(ctx)
    queue_url = _create_queue_subscribed_to_topic(ctx, topic_arn)

    # Positive control: publish directly (as the topic owner, who is always authorized) to
    # prove the SNS->SQS observation pipeline itself works before we probe the denied path.
    sns = ctx.client("sns")
    control_marker = ctx.unique_name("control-marker-")
    sns.publish(TopicArn=topic_arn, Message=json.dumps({"marker": control_marker}))
    control_messages = _wait_for_matching_message(ctx, queue_url, control_marker, timeout_s=60.0)
    assert control_messages, "positive control publish was never observed on the subscriber queue"

    source = ctx.unique_name("sim2real.evtnopol.src-")
    rule_name, rule_arn = _create_rule(ctx, source)
    # Deliberately break exactly one thing: do NOT grant events.amazonaws.com publish rights
    # on the topic policy.
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": topic_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.test",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    messages = _wait_for_matching_message(ctx, queue_url, marker, timeout_s=60.0)
    assert messages == [], f"message was published without a topic policy grant: {messages!r}"

    # Restore: grant events.amazonaws.com the exact publish right withheld above, then replay
    # an identical rule-triggered publish under a fresh marker. This proves the missing topic
    # policy was the only thing standing between the match and the message landing -- not a
    # delivery pipeline that silently never invokes SNS targets at all, which would also read
    # as "no message" above.
    _allow_events_to_publish(ctx, topic_arn, rule_arn)
    restored_marker = ctx.unique_name("restored-marker-")
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.test",
                "Detail": json.dumps({"marker": restored_marker}),
            }
        ]
    )
    restored_messages = _wait_for_matching_message(ctx, queue_url, restored_marker, timeout_s=60.0)
    assert restored_messages, "granting the topic policy did not unblock delivery of the identical rule/target"


def _create_topic(ctx):
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-evtnopol-topic-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _allow_events_to_publish(ctx, topic_arn, rule_arn):
    sns = ctx.client("sns")
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    policy_doc = json.loads(attrs["Policy"])
    policy_doc["Statement"].append(
        {
            "Sid": "AllowEventBridgePublish",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }
    )
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy_doc)
    )


def _create_queue_subscribed_to_topic(ctx, topic_arn):
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    q_name = ctx.unique_name("sim2real-evtnopol-queue-")
    url = sqs.create_queue(QueueName=q_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
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
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return url


def _create_rule(ctx, source):
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-evtnopol-rule-")
    pattern = json.dumps({"source": [source]})
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rule_arn = resp["RuleArn"]

    def _cleanup():
        try:
            targets = events.list_targets_by_rule(Rule=rule_name).get("Targets", [])
            if targets:
                events.remove_targets(Rule=rule_name, Ids=[t["Id"] for t in targets])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup)
    return rule_name, rule_arn


def _wait_for_matching_message(ctx, queue_url, marker, timeout_s=60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    matched = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in envelope.get("Message", ""):
                matched.append(envelope)
        if matched:
            return matched
    return matched


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
