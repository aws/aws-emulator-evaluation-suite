"""eventbridge-rule-disabled-no-delivery-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-disabled-no-delivery-negative"
GROUP = "permission-boundary"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A DISABLED rule never delivers a matching event to its queue (empty receive, queue depth "0")
    while an ENABLED rule on the same pattern delivers it, and re-enabling the rule restores
    delivery."""
    ctl_queue = _create_queue(ctx, "ctlrule-q")
    neg_queue = _create_queue(ctx, "disabledrule-q")
    pattern = {"source": [ctx.unique_name("sim2real.disabledtest.")], "detail-type": ["Disabled Rule Test"]}
    ctl_rule = _create_rule(ctx, "ctlrule", pattern)
    neg_rule = _create_rule(ctx, "disabledrule", pattern)
    _set_queue_policy(ctx, ctl_queue, ctl_rule["arn"])
    _set_queue_policy(ctx, neg_queue, neg_rule["arn"])
    _put_target(ctx, ctl_rule["name"], "1", ctl_queue["arn"])
    _put_target(ctx, neg_rule["name"], "1", neg_queue["arn"])

    events = ctx.client("events")
    sqs = ctx.client("sqs")

    # neg_rule is disabled before it has ever delivered anything, so neg_queue has no prior
    # traffic that a duplicate delivery could later be mistaken for.
    events.disable_rule(Name=neg_rule["name"])
    _poll_rule_state(ctx, neg_rule["name"], "DISABLED", timeout_s=30.0)

    # A new rule's target can take a while to go live, so resend until the control delivers.
    token = ctx.unique_name("sim2real-disabled-")
    send_time = time.monotonic()
    ctl_messages = []
    deadline = time.monotonic() + 180.0
    while not ctl_messages and time.monotonic() < deadline:
        events.put_events(
            Entries=[
                {
                    "Source": pattern["source"][0],
                    "DetailType": "Disabled Rule Test",
                    "Detail": json.dumps({"token": token}),
                }
            ]
        )
        ctl_messages = _poll_messages(ctx, ctl_queue["url"], min_count=1, timeout_s=15.0)
    assert len(ctl_messages) >= 1, "control (ENABLED rule) never delivered -- can't prove absence is suppression"
    ctl_body = json.loads(ctl_messages[0]["Body"])
    assert ctl_body["detail"]["token"] == token, (
        f"control message token mismatch: expected {token!r}, got {ctl_body['detail'].get('token')!r}"
    )
    delivery_latency_s = time.monotonic() - send_time

    # neg_queue has had at least as long as the control to receive the same event, so anything
    # here is over-delivery from the DISABLED rule, not propagation lag.
    absence_window_s = max(3.0 * delivery_latency_s, 15.0)
    _assert_absent(ctx, neg_queue["url"], timeout_s=absence_window_s)

    # Second independent observable: the queue's own reported depth, not just an empty receive.
    approx = sqs.get_queue_attributes(QueueUrl=neg_queue["url"], AttributeNames=["ApproximateNumberOfMessages"])[
        "Attributes"
    ]["ApproximateNumberOfMessages"]
    assert approx == "0", f"expected ApproximateNumberOfMessages == '0' while rule was DISABLED, got {approx!r}"

    # Positive control: re-enable the SAME disabled rule and confirm delivery resumes.
    events.enable_rule(Name=neg_rule["name"])
    _poll_rule_state(ctx, neg_rule["name"], "ENABLED", timeout_s=30.0)

    # The rule reads ENABLED before its targets are live again, so resend until one arrives.
    token_enabled = ctx.unique_name("sim2real-enabled-")
    messages = []
    deadline = time.monotonic() + 180.0
    while not messages and time.monotonic() < deadline:
        events.put_events(
            Entries=[
                {
                    "Source": pattern["source"][0],
                    "DetailType": "Disabled Rule Test",
                    "Detail": json.dumps({"token": token_enabled}),
                }
            ]
        )
        messages = _poll_messages(ctx, neg_queue["url"], min_count=1, timeout_s=15.0)
    assert len(messages) >= 1, "positive control failed: re-enabled rule never delivered the event"
    body = json.loads(messages[0]["Body"])
    assert body["detail"]["token"] == token_enabled, (
        f"re-enabled message token mismatch: expected {token_enabled!r}, got {body['detail'].get('token')!r}"
    )


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-{suffix}-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"})[
        "QueueUrl"
    ]
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
    resp = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    events.tag_resource(
        ResourceARN=resp["RuleArn"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real"}],
    )
    return {"name": name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, queue_arn: str, **extra) -> None:
    events = ctx.client("events")
    target = {"Id": target_id, "Arn": queue_arn, **extra}
    events.put_targets(Rule=rule_name, Targets=[target])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_rule_state(ctx, rule_name: str, expected_state: str, timeout_s: float = 30.0) -> None:
    events = ctx.client("events")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = events.describe_rule(Name=rule_name)["State"]
        if state == expected_state:
            return
        time.sleep(2)
    raise AssertionError(f"rule never reached state {expected_state}, last seen {state}")


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
        raise AssertionError(f"expected no message while the rule was disabled, got {len(leaked)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
