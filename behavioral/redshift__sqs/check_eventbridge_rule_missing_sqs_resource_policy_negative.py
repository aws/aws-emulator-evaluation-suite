"""eventbridge-rule-missing-sqs-resource-policy-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-missing-sqs-resource-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A rule's target queue with no policy granting events.amazonaws.com SendMessage never receives
    the matched event, while a queue on the same rule that carries the grant does."""
    queue_ok = _create_queue(ctx, "haspolicy-q")
    queue_bad = _create_queue(ctx, "nopolicy-q")  # deliberately left without a Policy attribute

    rule = _create_rule(
        ctx, "missingpolicy-rule", {"source": ["sim2real.missingpolicytest"], "detail-type": ["Missing Policy Test"]}
    )
    _set_queue_policy(ctx, queue_ok, rule["arn"])
    _put_target(ctx, rule["name"], "1", queue_ok["arn"])
    _put_target(ctx, rule["name"], "2", queue_bad["arn"])

    token = ctx.unique_name("sim2real-missingpolicy-token-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.missingpolicytest",
                "DetailType": "Missing Policy Test",
                "Detail": json.dumps({"token": token}),
            }
        ]
    )

    # Positive control: the properly-authorized queue receives the event.
    ok_messages = _poll_messages(ctx, queue_ok["url"], min_count=1, timeout_s=90.0)
    assert len(ok_messages) >= 1, "positive control failed: authorized queue never received the event"
    ok_body = json.loads(ok_messages[0]["Body"])
    assert ok_body["detail"]["token"] == token, (
        f"expected delivered detail.token == {token!r}, got {ok_body['detail'].get('token')!r}"
    )

    # The policy-less queue must never receive anything.
    _assert_absent(ctx, queue_bad["url"], timeout_s=40.0)


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{suffix}-"), tags={"sim2real": CHECK}
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        raise AssertionError(f"expected no message on the policy-less queue, got {len(leaked)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
