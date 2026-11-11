"""eventbridge-rule-event-pattern-mismatch-redshift-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-event-pattern-mismatch-redshift-negative"
GROUP = "permission-boundary"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A rule filtering detail.eventName ["CreateCluster"] delivers a CreateCluster event with its token
    and does not forward a DeleteCluster event on the same source (queue depth stays "0")."""
    queue = _create_queue(ctx, "patternmismatch-q")
    rule = _create_rule(
        ctx,
        "patternmismatch-rule",
        {
            "source": ["sim2real.redshift"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {"eventSource": ["redshift.amazonaws.com"], "eventName": ["CreateCluster"]},
        },
    )
    _set_queue_policy(ctx, queue, rule["arn"])
    _put_target(ctx, rule["name"], "1", queue["arn"])

    events = ctx.client("events")
    token_match = ctx.unique_name("sim2real-match-")
    positive_start = time.monotonic()
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(
                    {
                        "eventSource": "redshift.amazonaws.com",
                        "eventName": "CreateCluster",
                        "requestParameters": {"token": token_match},
                    }
                ),
            }
        ]
    )
    matched = _poll_messages(ctx, queue["url"], min_count=1, timeout_s=90.0)
    positive_latency_s = time.monotonic() - positive_start
    assert len(matched) >= 1, "positive control failed: matching eventName was never delivered"
    body = json.loads(matched[0]["Body"])
    assert body["detail"]["eventName"] == "CreateCluster"
    assert body["detail"]["requestParameters"]["token"] == token_match

    # Queue is now drained. A DeleteCluster event does not match the pattern. The absence
    # window must be at least as generous as the delivery path just proved itself to need,
    # or a correct-but-slower target would score as "blocked".
    token_mismatch = ctx.unique_name("sim2real-mismatch-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(
                    {
                        "eventSource": "redshift.amazonaws.com",
                        "eventName": "DeleteCluster",
                        "requestParameters": {"token": token_mismatch},
                    }
                ),
            }
        ]
    )
    absence_window_s = max(3 * positive_latency_s, 15.0)
    _assert_absent(ctx, queue["url"], timeout_s=absence_window_s)

    # Second independent observable: the queue's own reported depth, not just an empty receive.
    sqs = ctx.client("sqs")
    depth = sqs.get_queue_attributes(QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"])[
        "Attributes"
    ]["ApproximateNumberOfMessages"]
    assert depth == "0", f"expected ApproximateNumberOfMessages == 0 after the mismatch, got {depth}"


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{suffix}-"),
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
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


def _assert_absent(ctx, queue_url: str, timeout_s: float = 40.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    leaked = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            leaked.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if leaked:
            break
    if leaked:
        raise AssertionError(f"expected no message for the non-matching eventName, got {len(leaked)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
