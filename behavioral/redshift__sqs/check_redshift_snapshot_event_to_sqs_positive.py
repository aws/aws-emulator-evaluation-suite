"""redshift-snapshot-event-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "redshift-snapshot-event-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A Redshift-shaped CreateClusterSnapshot event matched by an eventName rule is delivered to SQS
    with its eventName and snapshotIdentifier intact."""
    snapshot_id = ctx.unique_name("sim2real-rs-snap-")
    cluster_id = ctx.unique_name("sim2real-rs-cluster-")

    queue = _create_queue(ctx, "snapevt-q")
    rule = _create_rule(
        ctx,
        "snapevt-rule",
        {
            "source": ["sim2real.redshift"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["redshift.amazonaws.com"],
                "eventName": ["CreateClusterSnapshot"],
            },
        },
    )
    _set_queue_policy(ctx, queue, rule["arn"])
    _put_target(ctx, rule["name"], "1", queue["arn"])

    events = ctx.client("events")
    entry = {
        "Source": "sim2real.redshift",
        "DetailType": "AWS API Call via CloudTrail",
        "Detail": json.dumps(
            {
                "eventSource": "redshift.amazonaws.com",
                "eventName": "CreateClusterSnapshot",
                "requestParameters": {
                    "clusterIdentifier": cluster_id,
                    "snapshotIdentifier": snapshot_id,
                },
            }
        ),
    }

    def _is_our_snapshot(body: dict) -> bool:
        return (
            body.get("detail", {}).get("requestParameters", {}).get("snapshotIdentifier")
            == snapshot_id
        )

    body = None
    for _ in range(4):
        events.put_events(Entries=[entry])
        body = _poll_matching(ctx, queue["url"], _is_our_snapshot, timeout_s=30.0)
        if body is not None:
            break
    assert body is not None, "snapshot-created event was never delivered to the target queue"
    assert body["detail"]["eventName"] == "CreateClusterSnapshot"
    assert body["detail"]["requestParameters"]["snapshotIdentifier"] == snapshot_id


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{suffix}-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url, "arn": _queue_arn(sqs, url)}


def _set_queue_policy(ctx, queue: dict, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeRule",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})


def _create_rule(ctx, suffix: str, pattern: dict) -> dict:
    events = ctx.client("events")
    name = ctx.unique_name(f"sim2real-{suffix}-")
    resp = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, queue_arn: str, **extra) -> None:
    events = ctx.client("events")
    target = {"Id": target_id, "Arn": queue_arn, **extra}
    events.put_targets(Rule=rule_name, Targets=[target])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_matching(ctx, queue_url: str, predicate, timeout_s: float = 30.0):
    sqs = ctx.client("sqs")
    found = None
    deadline = time.monotonic() + timeout_s
    while found is None and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            body = json.loads(m["Body"])
            if found is None and predicate(body):
                found = body
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
