"""sqs-queue-policy-wrong-source-arn-condition-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sqs-queue-policy-wrong-source-arn-condition-negative"
GROUP = "permission-boundary"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A queue policy whose aws:SourceArn condition names an unrelated rule ARN blocks delivery from the
    real rule, while a queue on the same rule whose condition names that rule receives the event."""
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    queue_good = _create_queue(ctx, "srcarn-good-q")
    queue_bad = _create_queue(ctx, "srcarn-bad-q")

    rule = _create_rule(
        ctx, "srcarn-rule", {"source": ["sim2real.srcarntest"], "detail-type": ["Source Arn Test"]}
    )
    unrelated_rule_name = ctx.unique_name("sim2real-unrelated-rule-")
    unrelated_rule_arn = f"arn:aws:events:{ctx.region}:{account}:rule/{unrelated_rule_name}"

    _set_queue_policy(ctx, queue_good, rule["arn"])  # correct condition
    _set_queue_policy(ctx, queue_bad, unrelated_rule_arn)  # wrong condition

    _put_target(ctx, rule["name"], "1", queue_good["arn"])
    _put_target(ctx, rule["name"], "2", queue_bad["arn"])

    token = ctx.unique_name("sim2real-srcarn-token-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.srcarntest",
                "DetailType": "Source Arn Test",
                "Detail": json.dumps({"token": token}),
            }
        ]
    )

    good_messages = _poll_messages(ctx, queue_good["url"], min_count=1, timeout_s=90.0)
    assert len(good_messages) >= 1, "positive control failed: correctly-scoped queue never received the event"
    body = json.loads(good_messages[0]["Body"])
    assert body["detail"]["token"] == token, (
        f"expected delivered detail.token {token!r}, got {body['detail'].get('token')!r}"
    )

    _assert_absent(ctx, queue_bad["url"], timeout_s=40.0)


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{suffix}-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url, "arn": _queue_arn(sqs, url)}


def _set_queue_policy(ctx, queue: dict, source_arn_condition: str) -> None:
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
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn_condition}},
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
        raise AssertionError(f"expected no message on the mis-scoped queue, got {len(leaked)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
