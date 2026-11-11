"""eventbridge-redshift-event-pattern-mismatch-no-delivery-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-redshift-event-pattern-mismatch-no-delivery-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Redshift-shaped event whose eventName does not match the rule's pattern is not delivered to
    the target queue, while a matching RebootCluster event on the same rule is."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rs-mismatch-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-rs-mismatch-rule-")
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

    def _cluster_event(event_name):
        return {
            "eventSource": "redshift.amazonaws.com",
            "eventName": event_name,
            "awsRegion": ctx.region,
            "requestParameters": {"clusterIdentifier": cluster_id},
        }

    # Mismatching event: eventName does not appear in the rule's pattern.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",

                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(_cluster_event("CreateClusterSnapshot")),
                "Resources": [
                    f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
                ],
                "EventBusName": "default",
            }
        ]
    )

    mismatch_msg = _wait_for_matching_message(
        sqs,
        queue_url,
        lambda d: d.get("detail", {}).get("requestParameters", {}).get(
            "clusterIdentifier"
        )
        == cluster_id,
        timeout_s=20,
    )
    assert mismatch_msg is None, "mismatched event was delivered despite not matching the pattern"

    # Matching event on the same rule/queue: proves the wiring is otherwise
    # sound. Rule/target/queue-policy wiring is eventually consistent on real
    # EventBridge; re-inject across several windows rather than one guess.
    match_entry = {
        "Source": "sim2real.redshift",

        "DetailType": "AWS API Call via CloudTrail",
        "Detail": json.dumps(_cluster_event("RebootCluster")),
        "Resources": [
            f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
        ],
        "EventBusName": "default",
    }
    match_msg = None
    for _ in range(4):
        events.put_events(Entries=[match_entry])
        match_msg = _wait_for_matching_message(
            sqs,
            queue_url,
            lambda d: d.get("detail", {}).get("requestParameters", {}).get(
                "clusterIdentifier"
            )
            == cluster_id,
            timeout_s=30,
        )
        if match_msg is not None:
            break
    assert match_msg is not None, "matching event was never delivered (wiring broken)"
    assert match_msg["detail"]["eventName"] == "RebootCluster", (
        f"expected delivered event eventName == RebootCluster, got "
        f"{match_msg['detail'].get('eventName')!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
