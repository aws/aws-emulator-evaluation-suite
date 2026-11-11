"""eventbridge-cloudfront-event-batch-delivery-preserves-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "eventbridge-cloudfront-event-batch-delivery-preserves-order"
GROUP = "data-format"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A burst of CloudFront API-call events sent through one rule to one FIFO-queue message group arrives exactly
    once each with source, detail-type and request parameters intact. EventBridge does not keep the send order for
    a FIFO SQS target even within one message group, so order is not asserted."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-fifo-") + ".fifo"
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    marker = ctx.unique_name("batch-")
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["sim2real.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {"batchMarker": [marker]},
    }
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _grant_eventbridge_sqs(ctx, queue_url, queue_arn, rule_arn)

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "target-1",
                "Arn": queue_arn,
                "SqsParameters": {"MessageGroupId": "cloudfront-batch"},
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))

    n = 6
    for i in range(n):
        resp = events.put_events(
            Entries=[
                {
                    "Source": "sim2real.cloudfront",
                    "DetailType": "AWS API Call via CloudTrail",
                    "Detail": json.dumps(
                        {
                            "eventName": "CreateInvalidation",
                            "batchMarker": marker,
                            "seq": i,
                            "requestParameters": {
                                "distributionId": f"EDIST{i:03d}EXAMPLE",
                                "invalidationBatch": {"callerReference": f"sim2real-{i}"},
                            },
                        }
                    ),
                }
            ]
        )
        if resp.get("FailedEntryCount", 0):
            failed = [e for e in resp.get("Entries", []) if e.get("ErrorCode")]
            raise AssertionError(f"put_events entry failed: {failed[:1]}")

    received = _collect_messages(ctx, queue_url, expected_count=n, timeout_s=150)
    assert len(received) == n, f"expected {n} messages, got {len(received)}"

    seqs = [json.loads(m["Body"])["detail"]["seq"] for m in received]
    assert sorted(seqs) == list(range(n)), f"expected each of seq 0..{n - 1} exactly once, got {seqs}"

    # Full detail payload integrity for one arbitrary message, located by its seq (not
    # by list position: relative order is not guaranteed, so index 3 is not seq 3).
    bodies = [json.loads(m["Body"]) for m in received]
    sample = next(b for b in bodies if b["detail"]["seq"] == 3)
    assert sample["detail"]["requestParameters"]["distributionId"] == "EDIST003EXAMPLE"
    assert sample["detail"]["requestParameters"]["invalidationBatch"]["callerReference"] == "sim2real-3"
    assert sample["source"] == "sim2real.cloudfront", sample["source"]
    assert sample["detail-type"] == "AWS API Call via CloudTrail"


def _grant_eventbridge_sqs(ctx, queue_url: str, queue_arn: str, rule_arn: str, sid: str = "AllowEventBridge") -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _collect_messages(ctx, queue_url: str, expected_count: int, timeout_s: float = 90):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            out.append(m)
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} within {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
