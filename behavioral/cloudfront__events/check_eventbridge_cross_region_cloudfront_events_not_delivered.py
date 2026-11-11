"""eventbridge-cross-region-cloudfront-events-not-delivered."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "eventbridge-cross-region-cloudfront-events-not-delivered"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule on one region's default event bus delivers nothing for an event put onto another region's default bus,
    and delivers the same kind of event put onto its own region's bus: each region's default bus is isolated."""
    from botocore.exceptions import EndpointConnectionError

    queue_url, queue_arn = _create_queue(ctx)
    rule_name = ctx.unique_name("sim2real-cf-xregion-rule-")
    events = ctx.client("events")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["sim2real.cloudfront.xregion"], "detail-type": ["CloudFront Cache Purge Requested"]}
        ),
        Tags=[{"Key": "sim2real", "Value": rule_name}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs = ctx.client("sqs")
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t"]))

    # us-east-1 / us-west-2 are the check's subject, not a pinned resource: it needs any region
    # other than ctx.region to prove default event buses are per-region isolated.
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    other_client = ctx.client("events", region=other_region)

    cross_marker = ctx.unique_name("cross-region-marker-")
    try:
        other_client.put_events(
            Entries=[
                {
                    "Source": "sim2real.cloudfront.xregion",
                    "DetailType": "CloudFront Cache Purge Requested",
                    "Detail": json.dumps({"marker": cross_marker}),
                }
            ]
        )
    except EndpointConnectionError as exc:

        raise AssertionError(f"second region ({other_region}) endpoint unreachable in this environment: {exc}")

    assert not _message_arrives(ctx, queue_url, "marker", cross_marker, timeout_s=25), (
        "an event PutEvents'd into a different region's bus was delivered to this region's rule"
    )

    same_region_marker = ctx.unique_name("same-region-marker-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront.xregion",
                "DetailType": "CloudFront Cache Purge Requested",
                "Detail": json.dumps({"marker": same_region_marker}),
            }
        ]
    )
    assert _message_arrives(ctx, queue_url, "marker", same_region_marker, timeout_s=60), (
        "positive control: same-region PutEvents never reached the rule's SQS target"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-cf-xregion-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": name})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _message_arrives(ctx, queue_url: str, key: str, value: str, timeout_s: float) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("detail", {}).get(key) == value:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
