"""redshift-cluster-event-rule-sqs-target-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "redshift-cluster-event-rule-sqs-target-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A Redshift-shaped CreateCluster event injected with PutEvents under a non-reserved source is
    delivered by the matching rule to SQS with its source, eventName and cluster id intact."""
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    cluster_id = ctx.unique_name("sim2real-rs-cluster-")

    queue = _create_queue(ctx, "clusterevt-q")
    rule = _create_rule(
        ctx,
        "clusterevt-rule",
        {
            "source": ["sim2real.redshift"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {"eventSource": ["redshift.amazonaws.com"], "eventName": ["CreateCluster"]},
        },
    )
    _set_queue_policy(ctx, queue, rule["arn"])
    _put_target(ctx, rule["name"], "1", queue["arn"])

    events = ctx.client("events")
    resource_arn = f"arn:aws:redshift:{ctx.region}:{account}:cluster:{cluster_id}"
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Resources": [resource_arn],
                "Detail": json.dumps(
                    {
                        "eventSource": "redshift.amazonaws.com",
                        "eventName": "CreateCluster",
                        "awsRegion": ctx.region,
                        "requestParameters": {"clusterIdentifier": cluster_id},
                    }
                ),
            }
        ]
    )

    messages = _poll_messages(ctx, queue["url"], min_count=1, timeout_s=90.0)
    assert len(messages) >= 1, "cluster state-change event was never delivered to the target queue"
    body = json.loads(messages[0]["Body"])
    assert body["source"] == "sim2real.redshift", f"expected source sim2real.redshift, got {body['source']!r}"
    assert body["detail"]["eventName"] == "CreateCluster", (
        f"expected detail.eventName CreateCluster, got {body['detail']['eventName']!r}"
    )
    assert body["detail"]["requestParameters"]["clusterIdentifier"] == cluster_id, (
        "expected detail.requestParameters.clusterIdentifier "
        f"{cluster_id!r}, got {body['detail']['requestParameters']['clusterIdentifier']!r}"
    )


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


def _poll_messages(ctx, queue_url: str, min_count: int = 1, timeout_s: float = 90.0):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
