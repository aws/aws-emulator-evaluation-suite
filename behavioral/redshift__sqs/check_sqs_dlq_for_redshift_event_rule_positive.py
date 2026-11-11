"""sqs-dlq-for-redshift-event-rule-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sqs-dlq-for-redshift-event-rule-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matched RebootCluster event the target queue may not receive is redirected to the target's
    dead-letter queue, and the unauthorized primary queue stays empty."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Primary target queue: deliberately left WITHOUT a resource policy granting
    # events.amazonaws.com sqs:SendMessage, so EventBridge delivery fails.
    primary_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rs-dlqprimary-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=primary_url))
    primary_arn = sqs.get_queue_attributes(
        QueueUrl=primary_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # Dead-letter queue: has the correct policy, keyed to the rule ARN.
    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rs-dlqdlq-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-rs-dlq-rule-")
    pattern = {
        "source": ["sim2real.redshift"],

        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["redshift.amazonaws.com"],
            "eventName": ["RebootCluster"],
        },
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]

    def _cleanup_rule():
        events.remove_targets(Rule=rule_name, Ids=["1"])
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup_rule)

    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSendToDLQ",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": dlq_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"Policy": json.dumps(dlq_policy)})

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "1",
                "Arn": primary_arn,
                "DeadLetterConfig": {"Arn": dlq_arn},
                "RetryPolicy": {
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                },
            }
        ],
    )

    cluster_id = ctx.unique_name("sim2real-rs-cluster-")
    detail = {
        "eventSource": "redshift.amazonaws.com",
        "eventName": "RebootCluster",
        "awsRegion": ctx.region,
        "requestParameters": {"clusterIdentifier": cluster_id},
    }
    entry = {
        "Source": "sim2real.redshift",

        "DetailType": "AWS API Call via CloudTrail",
        "Detail": json.dumps(detail),
        "Resources": [
            f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
        ],
        "EventBusName": "default",
    }
    dlq_msg = None
    for _ in range(4):
        events.put_events(Entries=[entry])
        dlq_msg = _wait_for_matching_message(
            sqs,
            dlq_url,
            lambda d: d.get("detail", {}).get("requestParameters", {}).get(
                "clusterIdentifier"
            )
            == cluster_id,
            timeout_s=30,
        )
        if dlq_msg is not None:
            break
    assert dlq_msg is not None, "failed delivery was never redirected to the dead-letter queue"
    assert dlq_msg["detail"]["eventName"] == "RebootCluster", (
        f"expected redirected detail.eventName RebootCluster, got {dlq_msg['detail']['eventName']!r}"
    )

    # The primary (unauthorized) queue must never have received the event.
    primary_attrs = sqs.get_queue_attributes(
        QueueUrl=primary_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(primary_attrs["ApproximateNumberOfMessages"]) == 0, (
        f"expected 0 messages on unauthorized primary queue, got "
        f"{primary_attrs['ApproximateNumberOfMessages']}"
    )
    leftover = sqs.receive_message(
        QueueUrl=primary_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
    )
    assert not leftover.get("Messages"), "unauthorized primary queue received the event"


def _wait_for_matching_message(sqs, queue_url, predicate, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            body: dict[str, Any] = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if predicate(body):
                return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
