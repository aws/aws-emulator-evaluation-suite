"""cloudfront-event-source-mismatch-not-delivered."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cloudfront-event-source-mismatch-not-delivered"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An EventBridge rule scoped to source=aws.cloudfront does not match an event
    published with a different source, so delivery does not occur, while a matching-source
    event from the same test IS delivered (positive control)."""
    events = ctx.client("events")
    rule = _create_rule(
        ctx,
        {
            "source": ["sim2real.cloudfront"],
            "detail-type": ["CloudFront Distribution State Change"],
        },
    )
    queue = _create_queue_for_events(ctx, rule["arn"])
    _put_target(ctx, rule["name"], "sqs-target", queue["arn"])

    matching_marker = ctx.unique_name("dist-match-")
    mismatched_marker = ctx.unique_name("dist-mismatch-")
    started = time.monotonic()
    entries = [
        {
            "Source": "sim2real.other-partner",
            "DetailType": "CloudFront Distribution State Change",
            "Detail": json.dumps(
                {
                    "distributionId": mismatched_marker,
                    "state": "Deployed",
                    "eTag": "E7MISMATCH",
                }
            ),
        },
        {
            "Source": "sim2real.cloudfront",
            "DetailType": "CloudFront Distribution State Change",
            "Detail": json.dumps(
                {
                    "distributionId": matching_marker,
                    "state": "Deployed",
                    "eTag": "E7MATCH",
                }
            ),
        },
    ]
    _put_all(events, entries)

    messages = _drain_queue(
        ctx,
        queue["url"],
        timeout_s=90.0,
        resend=lambda: _put_all(events, entries),
        until=lambda ms: any(matching_marker in m["Body"] for m in ms),
    )
    assert any(matching_marker in m["Body"] for m in messages), (
        "positive control failed: the matching-source event was never delivered"
    )
    # Every send carries both events, so a leaked one would arrive with the control: the hold
    # after it is 3x the control's arrival time from the first send, at least 15 s, at most 90 s.
    hold_s = min(90.0, max(15.0, 3.0 * (time.monotonic() - started)))
    messages += _drain_queue(ctx, queue["url"], timeout_s=hold_s)
    bodies = [m["Body"] for m in messages]
    assert not any(mismatched_marker in b for b in bodies), (
        "mismatched-source event was delivered despite the rule's source filter"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_rule(ctx, event_pattern: dict[str, Any]) -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfrule-")
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return {"name": rule_name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, target_arn: str) -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _create_queue_for_events(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name("sim2real-cfq-")
    url = sqs.create_queue(
        QueueName=q_name, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventsPublish",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _put_all(events, entries) -> None:
    """Publish ``entries``; every one must be accepted, or an absence proves nothing."""
    resp = events.put_events(Entries=entries)
    assert resp.get("FailedEntryCount", 0) == 0, f"put_events failed: {resp.get('Entries')}"


def _drain_queue(
    ctx, queue_url: str, timeout_s: float = 60.0, until=None, resend=None
) -> list[dict[str, Any]]:
    """Receive and delete messages until until(collected) holds, or for timeout_s without one.
    resend() runs every 15 s meanwhile, so delivery does not wait on EventBridge's retry backoff
    while the queue policy propagates."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    last_send = time.monotonic()
    while time.monotonic() < deadline:
        if resend is not None and time.monotonic() - last_send >= 15.0:
            resend()
            last_send = time.monotonic()
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, max(1, int(deadline - time.monotonic()))),
        )
        msgs = resp.get("Messages", [])
        for m in msgs:
            collected.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if until is not None and until(collected):
            break
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
