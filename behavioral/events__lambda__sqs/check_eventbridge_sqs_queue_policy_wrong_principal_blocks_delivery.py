"""eventbridge-sqs-queue-policy-wrong-principal-blocks-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-sqs-queue-policy-wrong-principal-blocks-delivery"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue policy granting another principal blocks delivery of matching events (queue depth
    stays 0); replacing it with an events.amazonaws.com grant delivers the next event."""
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")

    wrong_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WrongPrincipal",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(wrong_policy)})

    rule = _put_rule(
        ctx, pattern={"source": ["sim2real.policytest"], "detail-type": ["Ping"]}
    )
    _put_targets(ctx, rule["name"], [{"Id": "sqs-target", "Arn": queue["arn"]}])

    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.policytest",
                "DetailType": "Ping",
                "Detail": json.dumps({"seq": "wrong-principal"}),
            }
        ]
    )
    dropped = _collect_messages(ctx, queue["url"], observe_s=45.0)
    assert dropped == [], f"message delivered despite wrong queue-policy principal: {dropped}"
    depth = sqs.get_queue_attributes(QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"])[
        "Attributes"
    ]["ApproximateNumberOfMessages"]
    assert depth == "0", f"expected ApproximateNumberOfMessages=0 after blocked delivery, got {depth!r}"

    # Positive control: correct the policy to trust events.amazonaws.com and resend.
    account_id = queue["arn"].split(":")[4]
    correct_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account_id}:rule/*"
                    }
                },
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(correct_policy)}
    )
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.policytest",
                "DetailType": "Ping",
                "Detail": json.dumps({"seq": "correct-principal"}),
            }
        ]
    )
    delivered = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=60.0)
    assert len(delivered) >= 1, f"expected >=1 message after correcting queue policy, got {len(delivered)}"
    body = json.loads(delivered[0]["Body"])
    assert body["detail"]["seq"] == "correct-principal", (
        f"expected delivered detail.seq == 'correct-principal', got {body['detail'].get('seq')!r}"
    )


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url, max_messages=10, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _collect_messages(ctx, queue_url, observe_s=45.0):
    deadline = time.monotonic() + observe_s
    out = []
    while time.monotonic() < deadline:
        out.extend(_drain_queue(ctx, queue_url, wait_s=5))
    return out


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    out = []
    while time.monotonic() < deadline and len(out) < expected_count:
        out.extend(_drain_queue(ctx, queue_url, wait_s=5))
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)}")
    return out


def _put_rule(ctx, pattern=None, schedule=None, state="ENABLED", event_bus_name=None):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-ebl-rule-")
    kwargs: dict[str, Any] = {"Name": name, "State": state}
    if pattern is not None:
        kwargs["EventPattern"] = json.dumps(pattern)
    if schedule is not None:
        kwargs["ScheduleExpression"] = schedule
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_rule(**kwargs)
    if event_bus_name:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=event_bus_name))
    else:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_targets(ctx, rule_name, targets, event_bus_name=None):
    events = ctx.client("events")
    kwargs: dict[str, Any] = {"Rule": rule_name, "Targets": targets}
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_targets(**kwargs)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failures: {resp['FailedEntries']}")
    ids = [t["Id"] for t in targets]

    def _cleanup():
        kw: dict[str, Any] = {"Rule": rule_name, "Ids": ids}
        if event_bus_name:
            kw["EventBusName"] = event_bus_name
        events.remove_targets(**kw)

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
