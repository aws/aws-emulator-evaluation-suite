"""eventbridge-glue-job-state-change-message-attributes-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-glue-job-state-change-message-attributes-preserved"
GROUP = "data-format"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The full Glue job-run detail (jobName, jobRunId, state, message, and nested fields)
    survives EventBridge-to-SQS delivery unaltered in the message body, and the envelope
    fields (source, detail-type, resources) are preserved too."""
    queue_url, queue_arn = _create_queue(ctx)
    job_name = ctx.unique_name("sim2real-glue-job-")
    job_run_id = f"jr_{ctx.unique_name('')}"
    job_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:job/{job_name}"
    source = "sim2real.test.glue"
    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": [source],
            "detail-type": ["Glue Job State Change"],
        },
    )
    _wire_rule_to_queue(ctx, rule_name, rule_arn, queue_url, queue_arn)

    detail = {
        "jobName": job_name,
        "jobRunId": job_run_id,
        "state": "SUCCEEDED",
        "message": "Job run succeeded",
        "severity": "INFO",
        "startedOn": "2024-01-01T00:00:00.000Z",
        "completedOn": "2024-01-01T00:05:00.000Z",
        "nested": {"attempt": 2, "tags": ["etl", "nightly"], "meta": {"retries": 0}},
    }
    events = ctx.client("events")
    entries = [
        {
            "Source": source,
            "DetailType": "Glue Job State Change",
            "Resources": [job_arn],
            "Detail": json.dumps(detail),
        }
    ]

    messages = _deliver_and_wait(ctx, events, entries, queue_url, expected_min=1, timeout_s=90.0)
    assert len(messages) >= 1, "expected the job state event on the queue"
    body = json.loads(messages[0]["Body"])
    assert body["source"] == source, f"expected source {source!r}, got {body['source']!r}"
    assert body["detail-type"] == "Glue Job State Change", (
        f"expected detail-type 'Glue Job State Change', got {body['detail-type']!r}"
    )
    assert body["resources"] == [job_arn], f"expected resources [{job_arn!r}], got {body['resources']!r}"
    assert body["detail"] == detail, f"detail mutated in transit: {body['detail']!r}"


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
