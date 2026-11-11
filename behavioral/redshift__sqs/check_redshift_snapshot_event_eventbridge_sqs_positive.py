"""redshift-snapshot-event-eventbridge-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "redshift-snapshot-event-eventbridge-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Redshift-shaped CreateClusterSnapshot event injected with PutEvents is delivered to SQS with
    its eventName, cluster id and status "available" intact."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    resource_tags = {"sim2real:managed": "true", "sim2real:check": CHECK}

    queue_name = ctx.unique_name("sim2real-rs-snap-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=dict(resource_tags))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-rs-snap-rule-")
    pattern = {
        "source": ["sim2real.redshift"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["redshift.amazonaws.com"],
            "eventName": ["CreateClusterSnapshot"],
        },
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": k, "Value": v} for k, v in resource_tags.items()],
    )["RuleArn"]

    def _cleanup_rule():
        events.remove_targets(Rule=rule_name, Ids=["1"])
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup_rule)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])

    cluster_id = ctx.unique_name("sim2real-rs-cluster-")
    snapshot_id = ctx.unique_name("sim2real-rs-snapshot-")
    detail = {
        "eventVersion": "1.08",
        "eventSource": "redshift.amazonaws.com",
        "eventName": "CreateClusterSnapshot",
        "awsRegion": ctx.region,
        "requestParameters": {
            "clusterIdentifier": cluster_id,
            "snapshotIdentifier": snapshot_id,
        },
        "responseElements": {"status": "available", "snapshotType": "manual"},
    }
    entry = {
        "Source": "sim2real.redshift",

        "DetailType": "AWS API Call via CloudTrail",
        "Detail": json.dumps(detail),
        "Resources": [
            f"arn:aws:redshift:{ctx.region}:{account_id}:snapshot:{cluster_id}/{snapshot_id}"
        ],
        "EventBusName": "default",
    }

    msg = _send_and_wait(
        events,
        sqs,
        queue_url,
        entry,
        lambda d: d.get("detail", {}).get("requestParameters", {}).get(
            "snapshotIdentifier"
        )
        == snapshot_id,
        attempts=4,
        poll_s=30,
    )
    assert msg is not None, "snapshot completion event was never delivered to SQS"
    assert msg["detail"]["eventName"] == "CreateClusterSnapshot", (
        f"expected eventName CreateClusterSnapshot, got {msg['detail'].get('eventName')!r}"
    )
    assert msg["detail"]["requestParameters"]["clusterIdentifier"] == cluster_id, (
        f"expected clusterIdentifier {cluster_id!r}, got "
        f"{msg['detail']['requestParameters'].get('clusterIdentifier')!r}"
    )
    assert msg["detail"]["responseElements"]["status"] == "available", (
        f"expected responseElements.status 'available', got "
        f"{msg['detail']['responseElements'].get('status')!r}"
    )


def _wait_for_matching_message(sqs, queue_url, predicate, timeout_s=60.0):
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


def _send_and_wait(events, sqs, queue_url, entry, predicate, attempts=4, poll_s=30):
    """EventBridge rule/target/queue-policy wiring is eventually consistent on
    real AWS (propagation can lag well past a single short poll window).
    Re-inject the same event across several windows instead of guessing one
    fixed delay -- each re-send is a no-op from the assertion's perspective
    since the predicate matches on a unique id embedded in the event."""
    for _ in range(attempts):
        events.put_events(Entries=[entry])
        msg = _wait_for_matching_message(sqs, queue_url, predicate, timeout_s=poll_s)
        if msg is not None:
            return msg
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
