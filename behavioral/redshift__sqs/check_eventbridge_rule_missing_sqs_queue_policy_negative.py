"""eventbridge-rule-missing-sqs-queue-policy-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-missing-sqs-queue-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule never delivers a matching event to an SQS target whose queue policy
    lacks events.amazonaws.com sqs:SendMessage, while a sibling target on the SAME rule with
    that policy receives it, so the silence is caused by the missing permission."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    resource_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real"}

    unauthorized_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rs-noqpolicy-"), tags=resource_tags
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=unauthorized_url))
    unauthorized_arn = sqs.get_queue_attributes(
        QueueUrl=unauthorized_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    authorized_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rs-qpolicy-"), tags=resource_tags
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=authorized_url))
    authorized_arn = sqs.get_queue_attributes(
        QueueUrl=authorized_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-rs-noqpolicy-rule-")
    pattern = {
        "source": ["sim2real.redshift"],

        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["redshift.amazonaws.com"],
            "eventName": ["CreateClusterSnapshot"],
        },
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    events.tag_resource(
        ResourceARN=rule_arn,
        Tags=[{"Key": k, "Value": v} for k, v in resource_tags.items()],
    )

    def _cleanup_rule():
        events.remove_targets(Rule=rule_name, Ids=["1", "2"])
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup_rule)

    # Only the authorized queue gets a policy allowing EventBridge to deliver.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": authorized_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=authorized_url, Attributes={"Policy": json.dumps(policy)}
    )

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "1", "Arn": unauthorized_arn},
            {"Id": "2", "Arn": authorized_arn},
        ],
    )

    cluster_id = ctx.unique_name("sim2real-rs-cluster-")
    detail = {
        "eventSource": "redshift.amazonaws.com",
        "eventName": "CreateClusterSnapshot",
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

    # Positive control: the correctly-authorized sibling queue receives it.
    # Rule/target/queue-policy wiring is eventually consistent on real
    # EventBridge; re-inject across several windows rather than one guess.
    # Both targets are on the SAME rule and the SAME PutEvents call, so the
    # latency measured here is exactly the delivery latency the unauthorized
    # queue would have needed too -- it calibrates the absence window below.
    control_msg = None
    latency_s = None
    for _ in range(4):
        attempt_start = time.monotonic()
        events.put_events(Entries=[entry])
        control_msg = _wait_for_matching_message(
            sqs,
            authorized_url,
            lambda d: d.get("detail", {}).get("requestParameters", {}).get(
                "clusterIdentifier"
            )
            == cluster_id,
            timeout_s=30,
        )
        if control_msg is not None:
            latency_s = time.monotonic() - attempt_start
            break
    assert control_msg is not None, "positive-control queue never received the event"
    assert latency_s is not None, "the positive control's delivery latency was not measured"

    # Hold absence for at least 3x the measured positive-control delivery
    # latency on this same wiring, sampling repeatedly (bounded retry with a
    # deadline) rather than trusting a single fixed sleep -- a window shorter
    # than the check's own observed latency would score a correct-but-slower
    # target as blocked.
    window_s = min(max(3.0 * latency_s, 20.0), 90.0)
    deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < deadline:
        leaked = sqs.receive_message(
            QueueUrl=unauthorized_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        assert not leaked, (
            f"queue without a policy received the event during the "
            f"{window_s:.0f}s absence window (measured control latency "
            f"{latency_s:.1f}s): {leaked!r}"
        )
        samples += 1
    assert samples >= 2, f"absence window took too few samples to be meaningful: {samples}"

    unauthorized_attrs = sqs.get_queue_attributes(
        QueueUrl=unauthorized_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(unauthorized_attrs["ApproximateNumberOfMessages"]) == 0, (
        f"expected ApproximateNumberOfMessages == 0 for the unauthorized queue, "
        f"got {unauthorized_attrs['ApproximateNumberOfMessages']!r}"
    )


# ===== helpers =====
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
