"""eventbridge-put-events-custom-source-mismatched-not-matched."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-put-events-custom-source-mismatched-not-matched"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """In one PutEvents call, an event whose source does not match a rule's filter never reaches
    that rule's queue while a matching event reaches a sibling rule's queue; an entry forging
    Source 'aws.backup' is rejected with NotAuthorizedForSourceException."""
    detail = json.dumps({"backupJobId": ctx.unique_name("job-"), "state": "COMPLETED"})

    mismatched_rule, mismatched_arn = _create_rule(
        ctx, {"source": ["aws.backup"], "detail-type": ["Backup Job State Change"]}
    )
    mismatched_url, mismatched_qarn = _create_queue_for_rule(ctx, mismatched_arn)
    _bind_target(ctx, mismatched_rule, mismatched_qarn)

    matching_source = ctx.unique_name("sim2real.backup.")
    matching_rule, matching_arn = _create_rule(
        ctx, {"source": [matching_source], "detail-type": ["Backup Job State Change"]}
    )
    matching_url, matching_qarn = _create_queue_for_rule(ctx, matching_arn)
    _bind_target(ctx, matching_rule, matching_qarn)

    # Reserved-source rejection: PutEvents refuses a customer-forged "aws.backup"
    # source outright, per-entry, before any rule pattern is even evaluated.
    forged_resp = ctx.client("events").put_events(
        Entries=[{"Source": "aws.backup", "DetailType": "Backup Job State Change", "Detail": detail}]
    )
    assert forged_resp["FailedEntryCount"] == 1, f"expected the forged entry to be rejected: {forged_resp}"
    forged_entry = forged_resp["Entries"][0]
    assert forged_entry.get("ErrorCode") == "NotAuthorizedForSourceException", (
        f"expected NotAuthorizedForSourceException, got {forged_entry}"
    )
    assert forged_entry.get("ErrorMessage") == "Not authorized for the source.", (
        f"expected ErrorMessage 'Not authorized for the source.', got {forged_entry}"
    )

    # One PutEvents call, two entries, two rules, evaluated at the same instant:
    # a mismatched (but legal, non-reserved) source, and a matching synthetic source.
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "custom.mismatched.source",
                "DetailType": "Backup Job State Change",
                "Detail": detail,
            },
            {
                "Source": matching_source,
                "DetailType": "Backup Job State Change",
                "Detail": detail,
            },
        ]
    )

    delivered = _poll_sqs_for_event(ctx, matching_url, lambda d: True, timeout_s=60)
    assert delivered["source"] == matching_source
    assert delivered["detail-type"] == "Backup Job State Change"

    # The mismatched rule's queue must receive neither entry -- checked after the
    # matching leg already proved delivery latency on this wiring is well under 60s.
    _assert_no_message(ctx, mismatched_url, wait_s=20.0)


def _create_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-bkp-rule-")
    arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")[
        "RuleArn"
    ]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name, arn


def _create_queue_for_rule(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-bkp-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _bind_target(ctx, rule_name: str, target_arn: str, target_id: str = "target-1") -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_sqs_for_event(ctx, queue_url: str, predicate, timeout_s: float = 60.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except ValueError:
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body is not None and predicate(body):
                return body
    raise AssertionError(f"expected event not observed within {timeout_s}s")


def _assert_no_message(ctx, queue_url: str, wait_s: float = 20.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        remaining = max(1.0, deadline - time.monotonic())
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=int(min(10, remaining))
        )
        msgs = resp.get("Messages", [])
        if msgs:
            raise AssertionError(f"unexpected message delivered: {msgs[0].get('Body')}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
