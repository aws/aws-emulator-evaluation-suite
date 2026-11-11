"""eventbridge-rule-pattern-mismatch-glue-source-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-pattern-mismatch-glue-source-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A "Glue Job State Change" event is delivered with detail.state "SUCCEEDED" to the queue of the
    rule whose pattern matches it, and the queue of a rule requiring source "aws.ec2" receives nothing.
    The event uses a non-reserved source: PutEvents refuses "aws.glue" from callers other than Glue."""
    job_name = ctx.unique_name("sim2real-glue-job-")

    mismatched_rule, mismatched_arn = _create_rule(
        ctx, {"source": ["aws.ec2"], "detail-type": ["EC2 Instance State-change Notification"]}
    )
    mismatched_url, mismatched_qarn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, mismatched_url, mismatched_qarn, mismatched_arn)
    _put_sqs_target(ctx, mismatched_rule, mismatched_qarn)

    matching_rule, matching_arn = _create_rule(
        ctx,
        {
            "source": ["sim2real.glue"],
            "detail-type": ["Glue Job State Change"],
            "detail": {"jobName": [job_name]},
        },
    )
    matching_url, matching_qarn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, matching_url, matching_qarn, matching_arn)
    _put_sqs_target(ctx, matching_rule, matching_qarn)

    ctx.client("events")

    def _entries():
        return [
            {
                "Source": "sim2real.glue",
                "DetailType": "Glue Job State Change",
                "Detail": json.dumps(
                    {"jobName": job_name, "state": "SUCCEEDED", "jobRunId": "jr_test"}
                ),
            }
        ]

    # Positive control: the matching rule delivers the event. Resending it periodically absorbs
    # SQS queue-policy propagation lag without waiting on EventBridge's slower retry backoff.
    started = time.monotonic()
    body = _send_until_received(
        ctx,
        _entries,
        matching_url,
        lambda b: isinstance(b, dict) and b.get("detail", {}).get("jobName") == job_name,
        timeout_s=150.0,
    )
    assert body["detail"]["state"] == "SUCCEEDED", (
        f"positive control: expected delivered event detail.state == 'SUCCEEDED', got {body['detail'].get('state')!r}"
    )

    # The mismatched-pattern rule's queue must never receive it, even after the same resends.
    # The same events would carry a leak, so the window is 3x the control's arrival time, at
    # least 15 s and never more than 60 s.
    window_s = min(60.0, max(15.0, 3.0 * (time.monotonic() - started)))
    messages = _collect_messages(ctx, mismatched_url, window_s=window_s)
    assert messages == [], (
        f"expected 0 messages on the mismatched-pattern rule's queue, got {len(messages)}: {messages!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-rule-")
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-glue-evt-")
    url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _set_queue_policy_for_rule(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _put_sqs_target(ctx, rule_name: str, queue_arn: str) -> None:
    events = ctx.client("events")
    target_id = "sim2real-target"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _send_until_received(
    ctx,
    entries_factory,
    queue_url: str,
    predicate,
    *,
    timeout_s: float = 150.0,
    resend_interval_s: float = 20.0,
):
    """Resends the PutEvents entries periodically while polling the queue, to
    absorb SQS resource-policy / EventBridge target propagation lag rather than
    depending on EventBridge's own (much slower) internal retry backoff."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    last_send = 0.0
    found: Any = None
    while time.monotonic() < deadline and found is None:
        if time.monotonic() - last_send >= resend_interval_s:
            put_resp = events.put_events(Entries=entries_factory())
            if put_resp.get("FailedEntryCount", 0):
                raise AssertionError(f"PutEvents entry failed: {put_resp['Entries']}")
            last_send = time.monotonic()
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found is None and predicate(body):
                found = body
    if found is None:
        raise AssertionError(
            f"matching SQS message not received within {timeout_s}s"
        )
    return found


def _drain_queue_until_match(ctx, queue_url: str, predicate, timeout_s=300.0, interval_s=5.0):
    sqs = ctx.client("sqs")
    found: dict[str, Any] = {"msg": None}

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found["msg"] is None and predicate(body):
                found["msg"] = body
        return found["msg"]

    _poll_until(
        probe,
        lambda v: v is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="matching SQS message",
    )
    return found["msg"]


def _collect_messages(ctx, queue_url: str, window_s: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(10, max(1, int(deadline - time.monotonic()))),
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
