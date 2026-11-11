"""eventbridge-rule-pattern-mismatch-suppresses-backup-event."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-pattern-mismatch-suppresses-backup-event"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule requiring detail-type 'Restore Job State Change' does not deliver a 'Backup Job State
    Change' event on the same custom source, and delivers a matching Restore Job event."""
    events = ctx.client("events")
    backup_source = "sim2real.backup"

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": [backup_source], "detail-type": ["Restore Job State Change"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    # The SQS resource policy just attached can take up to ~60s to propagate, and
    # EventBridge does not retry a target invocation that hit AccessDenied during that
    # window -- it drops the event for good. Prove the wiring (pattern match + queue
    # policy + target) is actually live, with fresh markers so the retry itself can't
    # be mistaken for "the rule correctly blocked delivery", before using this same
    # queue as the witness for the detail-type mismatch below.
    _retry_put_events_until_seen(ctx, events, queue["url"], backup_source, timeout_s=90.0)

    mismatched_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": mismatched_marker, "state": "COMPLETED"}),
            }
        ]
    )
    _assert_no_message_matching(ctx, queue["url"], lambda evt: _marker_in(evt, mismatched_marker), duration_s=20.0)

    matching_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Restore Job State Change",
                "Detail": json.dumps({"restoreJobId": matching_marker, "status": "COMPLETED"}),
            }
        ]
    )
    event = _wait_for_event_matching(
        ctx, queue["url"], lambda evt: _marker_in(evt, matching_marker), timeout_s=60.0, interval_s=5.0
    )
    got_detail_type = event["detail-type"]
    assert got_detail_type == "Restore Job State Change", (
        f"expected delivered event detail-type 'Restore Job State Change', got {got_detail_type!r}"
    )
    got_restore_job_id = event["detail"]["restoreJobId"]
    assert got_restore_job_id == matching_marker, (
        f"expected delivered event detail.restoreJobId {matching_marker!r}, got {got_restore_job_id!r}"
    )


def _marker_in(evt: dict[str, Any], marker: str) -> bool:
    detail = evt.get("detail", {})
    return marker in (detail.get("backupJobId"), detail.get("restoreJobId"))


def _retry_put_events_until_seen(ctx, events, queue_url: str, source: str, *, timeout_s: float = 90.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        marker = str(uuid.uuid4())
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Restore Job State Change",
                    "Detail": json.dumps({"restoreJobId": marker, "status": "COMPLETED"}),
                }
            ]
        )
        poll_deadline = time.monotonic() + 10.0
        while time.monotonic() < poll_deadline:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
            for msg in resp.get("Messages", []):
                body = json.loads(msg["Body"])
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                if _marker_in(body, marker):
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
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s")


def _assert_no_message_matching(ctx, queue_url: str, match_fn, duration_s: float = 20.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                raise AssertionError(f"mismatched event unexpectedly delivered: {body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
