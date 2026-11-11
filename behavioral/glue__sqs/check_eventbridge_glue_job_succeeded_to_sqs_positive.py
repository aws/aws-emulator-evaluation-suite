"""eventbridge-glue-job-succeeded-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-glue-job-succeeded-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue Job State Change SUCCEEDED event matched by an EventBridge rule is delivered
    to the target SQS queue."""
    queue_url, queue_arn = _create_queue(ctx)
    job_name = ctx.unique_name("sim2real-glue-job-")
    job_run_id = f"jr_{ctx.unique_name('')}"
    source = "sim2real.test.glue"
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
    entries = [
        {
            "Source": source,
            "DetailType": "Glue Job State Change",
            "Detail": json.dumps(
                {
                    "jobName": job_name,
                    "jobRunId": job_run_id,
                    "state": "SUCCEEDED",
                    "message": "Job run succeeded",
                    "severity": "INFO",
                }
            ),
        }
    ]
    put_resp = events.put_events(Entries=entries)
    if put_resp.get("FailedEntryCount", 0) != 0:
        err = put_resp["Entries"][0]
        raise AssertionError(f"code={err.get('ErrorCode')} msg={err.get('ErrorMessage')}")

    # Newly created rule/target wiring is eventually consistent -- resend the event
    # periodically while polling, in case the rule wasn't yet active for the first send.
    messages = _deliver_and_wait(ctx, events, entries, queue_url, expected_min=1, timeout_s=90.0)
    assert len(messages) >= 1, "expected the SUCCEEDED job state event on the queue"
    body = json.loads(messages[0]["Body"])
    assert body["detail-type"] == "Glue Job State Change", (
        f"expected detail-type='Glue Job State Change', got {body['detail-type']!r}"
    )
    assert body["source"] == source, f"expected source={source!r}, got {body['source']!r}"
    assert body["detail"]["state"] == "SUCCEEDED", (
        f"expected detail.state='SUCCEEDED', got {body['detail']['state']!r}"
    )
    assert body["detail"]["jobName"] == job_name, (
        f"expected detail.jobName={job_name!r}, got {body['detail']['jobName']!r}"
    )
    assert body["detail"]["jobRunId"] == job_run_id, (
        f"expected detail.jobRunId={job_run_id!r}, got {body['detail']['jobRunId']!r}"
    )


# ===== helpers =====
def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-sqs-"),
        tags={"sim2real-check": CHECK},
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    """Resend the PutEvents entries periodically while polling SQS.

    A freshly created EventBridge rule + target (and a freshly set SQS queue policy) are
    eventually consistent -- the very first PutEvents call can race the rule becoming active
    and simply not match anything (EventBridge does not replay events). Resending the same
    entries every few seconds while polling absorbs that propagation delay deterministically
    instead of guessing a fixed sleep.
    """
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
