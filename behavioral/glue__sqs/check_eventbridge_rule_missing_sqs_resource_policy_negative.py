"""eventbridge-rule-missing-sqs-resource-policy-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-missing-sqs-resource-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without an SQS queue policy granting events.amazonaws.com SendMessage, a matched Glue job
    state event is never delivered to the queue; granting the policy and resending delivers it,
    so the wiring itself is otherwise correct."""
    queue_url, queue_arn = _create_queue(ctx)
    job_name = ctx.unique_name("sim2real-glue-job-")
    source = "sim2real.test.glue"
    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": [source],
            "detail-type": ["Glue Job State Change"],
            "detail": {"state": ["SUCCEEDED"]},
        },
    )
    events = ctx.client("events")
    # Target is registered, but the queue's access policy is left at its default (empty) --
    # only the queue owner's IAM principals can act on it; events.amazonaws.com is not granted.
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])

    def _cleanup_targets() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=["1"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup_targets)

    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "Glue Job State Change",
                "Detail": json.dumps(
                    {"jobName": job_name, "jobRunId": "jr_blocked", "state": "SUCCEEDED"}
                ),
            }
        ]
    )
    blocked = _receive_messages(ctx, queue_url, expected_min=1, timeout_s=40.0)
    assert len(blocked) == 0, (
        "event was delivered to SQS despite the queue having no policy granting "
        "events.amazonaws.com sqs:SendMessage"
    )

    # Positive control: grant the policy, then the exact same event pattern delivers fine.
    # A freshly set queue policy is also eventually consistent, so resend while polling.
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
    entries = [
        {
            "Source": source,
            "DetailType": "Glue Job State Change",
            "Detail": json.dumps(
                {"jobName": job_name, "jobRunId": "jr_allowed", "state": "SUCCEEDED"}
            ),
        }
    ]
    delivered = _deliver_and_wait(ctx, events, entries, queue_url, expected_min=1, timeout_s=90.0)
    assert len(delivered) >= 1, "positive control: event should be delivered once policy is granted"
    body = json.loads(delivered[0]["Body"])
    assert body["detail"]["jobRunId"] == "jr_allowed", (
        f"expected delivered detail.jobRunId == 'jr_allowed', got {body['detail'].get('jobRunId')!r}"
    )


# ===== helpers =====
def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-sqs-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-glue-rule-")
    rule_arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    return name, rule_arn


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

