"""eventbridge-rule-disabled-does-not-deliver-backup-event."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-disabled-does-not-deliver-backup-event"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A disabled EventBridge rule does not deliver a matching backup-shaped event to its SQS queue.

    Re-enabling the same rule restores delivery for a later matching event (positive control).
    """
    events = ctx.client("events")
    # EventBridge drops customer PutEvents entries with a reserved "aws." source.
    backup_source = "sim2real.backup"

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": [backup_source], "detail-type": ["Backup Job State Change"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    # The new SQS queue policy can take ~60s to propagate and EventBridge drops (does not retry) an
    # AccessDenied delivery, so prove the wiring is live before using the queue as the witness.
    _retry_put_events_until_seen(ctx, events, queue["url"], backup_source, timeout_s=90.0)

    events.disable_rule(Name=rule_name)
    state = events.describe_rule(Name=rule_name)["State"]
    assert state == "DISABLED", f"expected rule state DISABLED after disable_rule, got {state!r}"

    disabled_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": disabled_marker, "state": "COMPLETED"}),
            }
        ]
    )
    _assert_no_message_matching(ctx, queue["url"], lambda evt: _job_id_in(evt, disabled_marker), duration_s=20.0)

    events.enable_rule(Name=rule_name)
    _poll_until(
        lambda: events.describe_rule(Name=rule_name)["State"], lambda s: s == "ENABLED", timeout_s=30.0, interval_s=2.0,
        description="rule ENABLED",
    )

    enabled_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": enabled_marker, "state": "COMPLETED"}),
            }
        ]
    )
    event = _wait_for_event_matching(
        ctx, queue["url"], lambda evt: _job_id_in(evt, enabled_marker), timeout_s=60.0, interval_s=5.0
    )
    got = event["detail"]["backupJobId"]
    assert got == enabled_marker, f"expected delivered event detail.backupJobId {enabled_marker!r}, got {got!r}"


def _job_id_in(evt: dict[str, Any], marker: str) -> bool:
    return evt.get("detail", {}).get("backupJobId") == marker


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_put_events_until_seen(ctx, events, queue_url: str, source: str, *, timeout_s: float = 90.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        marker = str(uuid.uuid4())
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Backup Job State Change",
                    "Detail": json.dumps({"backupJobId": marker, "state": "COMPLETED"}),
                }
            ]
        )
        poll_deadline = time.monotonic() + 10.0
        while time.monotonic() < poll_deadline:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
            for msg in resp.get("Messages", []):
                body = json.loads(msg["Body"])
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                if _job_id_in(body, marker):
                    return
    raise AssertionError(f"warm-up event never reached {queue_url} within {timeout_s}s of retrying")


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-evtq-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
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


def _wait_for_event_matching(
    ctx, queue_url: str, match_fn, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            seen.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s; saw {seen!r}")


def _assert_no_message_matching(ctx, queue_url: str, match_fn, duration_s: float = 20.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                raise AssertionError(f"disabled rule unexpectedly delivered an event: {body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
