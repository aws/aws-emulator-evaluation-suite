"""eventbridge-rule-pattern-mismatch-no-delivery-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-pattern-mismatch-no-delivery-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job state event whose detail.state does not match the rule's content filter produces
    no message on the SQS target; a matching event on the same rule and queue, sent first, proves
    the wiring delivers and sizes the window the unmatched event must clear."""
    queue_url, queue_arn = _create_queue(ctx)
    job_name = ctx.unique_name("sim2real-glue-job-")
    source = "sim2real.test.glue"
    # Rule only matches SUCCEEDED job-state events -- fully and correctly wired to the queue.
    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": [source],
            "detail-type": ["Glue Job State Change"],
            "detail": {"state": ["SUCCEEDED"]},
        },
    )
    _wire_rule_to_queue(ctx, rule_name, rule_arn, queue_url, queue_arn)

    events = ctx.client("events")

    # Positive control FIRST: an event that satisfies the filter is delivered. The rule's
    # target wiring and the queue policy are both eventually consistent, so resend while
    # polling, and measure how long propagation actually took on this exact wiring.
    match_entries = [
        {
            "Source": source,
            "DetailType": "Glue Job State Change",
            "Detail": json.dumps(
                {"jobName": job_name, "jobRunId": "jr_match", "state": "SUCCEEDED"}
            ),
        }
    ]
    control_start = time.monotonic()
    matched = _deliver_and_wait(
        ctx, events, match_entries, queue_url, expected_min=1, timeout_s=90.0
    )
    positive_latency_s = time.monotonic() - control_start
    assert len(matched) >= 1, "positive control: matching event should be delivered"
    body = json.loads(matched[0]["Body"])
    assert body["detail"]["jobRunId"] == "jr_match", (
        f"expected jobRunId 'jr_match', got {body['detail'].get('jobRunId')!r}"
    )
    assert body["detail"]["state"] == "SUCCEEDED", (
        f"expected state 'SUCCEEDED', got {body['detail'].get('state')!r}"
    )

    # Drain any at-least-once duplicate redelivery of the positive-control message before
    # testing absence, so a late duplicate cannot be mistaken for the mismatched event below.
    _receive_messages(ctx, queue_url, expected_min=10**9, timeout_s=5.0)

    # Mismatched: same source/detail-type, but state=FAILED does not satisfy the filter.
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "Glue Job State Change",
                "Detail": json.dumps(
                    {"jobName": job_name, "jobRunId": "jr_mismatch", "state": "FAILED"}
                ),
            }
        ]
    )
    # Hold absence for >=3x the positive control's own demonstrated propagation latency on
    # this same wiring (floored at 15s) -- a shorter window would score a target that is
    # merely slow to (mis)deliver as having correctly filtered.
    absence_window_s = max(15.0, 3.0 * positive_latency_s)
    mismatched = _receive_messages(ctx, queue_url, expected_min=1, timeout_s=absence_window_s)
    assert len(mismatched) == 0, (
        "a FAILED job-state event was delivered by a rule filtered to state=SUCCEEDED only "
        f"(waited {absence_window_s:.1f}s, >=3x the {positive_latency_s:.1f}s positive-control "
        "latency measured on this same wiring)"
    )


# ===== helpers =====
def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-glue-sqs-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-glue-rule-")
    rule_arn = events.put_rule(
        Name=name, EventPattern=json.dumps(event_pattern), State="ENABLED"
    )["RuleArn"]

    def _cleanup() -> None:
        try:
            events.remove_targets(Rule=name, Ids=["1"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=name)

    ctx.on_cleanup(_cleanup)
    return name, rule_arn


def _wire_rule_to_queue(ctx, rule_name: str, rule_arn: str, queue_url: str, queue_arn: str) -> None:
    sqs = ctx.client("sqs")
    events = ctx.client("events")
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
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])


def _receive_messages(
    ctx, queue_url: str, expected_min: int = 1, timeout_s: float = 45.0
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_min and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _deliver_and_wait(
    ctx,
    events_client,
    entries: list[dict[str, Any]],
    queue_url: str,
    expected_min: int = 1,
    timeout_s: float = 90.0,
    resend_interval_s: float = 10.0,
) -> list[dict[str, Any]]:
    """Resend the PutEvents entries periodically while polling SQS (absorbs EventBridge
    rule/target and SQS queue-policy propagation delay instead of a fixed sleep)."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    next_send = 0.0
    while time.monotonic() < deadline and len(out) < expected_min:
        now = time.monotonic()
        if now >= next_send:
            events_client.put_events(Entries=entries)
            next_send = now + resend_interval_s
        wait_s = int(max(1.0, min(5.0, next_send - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
