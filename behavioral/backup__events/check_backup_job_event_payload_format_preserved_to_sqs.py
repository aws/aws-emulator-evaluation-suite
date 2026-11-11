"""backup-job-event-payload-format-preserved-to-sqs."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "backup-job-event-payload-format-preserved-to-sqs"
GROUP = "data-format"
SERVICES = ["backup", "events"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:representation",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutEvents rejects a customer entry with Source 'aws.backup' with
    NotAuthorizedForSourceException, and a Backup-shaped event on a custom source reaches the SQS
    target with every field name, type and value intact."""
    events = ctx.client("events")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    control_source = ctx.unique_name("sim2real.backup-test.")
    pattern = {"source": ["aws.backup", control_source], "detail-type": ["Backup Job State Change"]}
    rule_name = ctx.unique_name("sim2real-rule-")
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    def _detail_for(job_id: str) -> dict[str, Any]:
        return {
            "backupJobId": job_id,
            "backupSizeInBytes": "36048",
            "backupVaultArn": f"arn:aws:backup:{ctx.region}:{account_id}:backup-vault:sim2real-vault",
            "backupVaultName": "sim2real-vault",
            "bytesTransferred": "36048",
            "creationDate": "2020-07-15T21:40:31.207Z",
            "iamRoleArn": f"arn:aws:iam::{account_id}:role/sim2real-role",
            "resourceArn": f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/sim2real-table",
            "resourceType": "DynamoDB",
            "state": "COMPLETED",
            "completionDate": "2020-07-15T21:41:05.921Z",
            "startBy": "2020-07-16T05:40:31.207Z",
            "percentDone": 100,
            "retryCount": 3,
        }

    # --- Positive control: a legal, non-reserved source delivers the same
    # Backup-shaped payload to SQS with every field preserved verbatim. Proves the
    # account, the rule and the transport are otherwise healthy before the negative
    # leg below claims a divergence.
    control_job_id = str(uuid.uuid4())
    control_detail = _detail_for(control_job_id)
    control_resources = [f"arn:aws:backup:{ctx.region}:{account_id}:recovery-point:sim2real-rp-control"]
    control_resp = events.put_events(
        Entries=[
            {
                "Source": control_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps(control_detail),
                "Resources": control_resources,
            }
        ]
    )
    assert control_resp["FailedEntryCount"] == 0, f"positive control PutEvents failed: {control_resp['Entries']}"

    control_start = time.monotonic()
    delivered = _wait_for_event_matching(
        ctx, queue["url"], lambda evt: evt.get("detail", {}).get("backupJobId") == control_job_id, timeout_s=200.0, interval_s=5.0
    )
    control_latency_s = time.monotonic() - control_start

    assert delivered["source"] == control_source, f"source mutated: {delivered['source']!r} != {control_source!r}"
    assert delivered["detail-type"] == "Backup Job State Change", (
        f"detail-type mutated: {delivered['detail-type']!r} != 'Backup Job State Change'"
    )
    assert delivered["resources"] == control_resources, (
        f"resources mutated: {delivered['resources']!r} != {control_resources!r}"
    )
    for key, value in control_detail.items():
        assert delivered["detail"][key] == value, f"field {key} mutated: {delivered['detail'][key]!r} != {value!r}"
    assert set(delivered["detail"].keys()) == set(control_detail.keys()), "extra or missing detail fields on delivery"

    # --- Break exactly one thing: reuse the AWS-reserved "aws.backup" source, which
    # no customer PutEvents call may claim.
    spoof_job_id = str(uuid.uuid4())
    spoof_detail = _detail_for(spoof_job_id)
    spoof_resp = events.put_events(
        Entries=[
            {
                "Source": "aws.backup",
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps(spoof_detail),
                "Resources": [f"arn:aws:backup:{ctx.region}:{account_id}:recovery-point:sim2real-rp-spoof"],
            }
        ]
    )
    assert spoof_resp["FailedEntryCount"] == 1, f"spoofed aws.backup PutEvents unexpectedly succeeded: {spoof_resp}"
    error_code = spoof_resp["Entries"][0].get("ErrorCode")
    assert error_code == "NotAuthorizedForSourceException", (
        f"expected NotAuthorizedForSourceException for a spoofed reserved source, got {error_code!r}: {spoof_resp['Entries'][0]}"
    )
    error_message = spoof_resp["Entries"][0].get("ErrorMessage")
    assert error_message == "Not authorized for the source.", (
        f"NotAuthorizedForSourceException message {error_message!r}, expected 'Not authorized for the source.'"
    )

    # --- Effect absent, via an independent read: an entry PutEvents itself rejected
    # must never reach the destination. Hold the window to >=3x the measured positive
    # latency so a correct-but-slow target is never mistaken for a blocked one.
    absence_window_s = max(15.0, 3.0 * control_latency_s)
    leaked = _poll_for_event(
        ctx, queue["url"], lambda evt: evt.get("detail", {}).get("backupJobId") == spoof_job_id, timeout_s=absence_window_s
    )
    assert leaked is None, (
        f"a PutEvents entry AWS itself rejected (NotAuthorizedForSourceException) was nonetheless "
        f"delivered to the SQS target: {leaked!r}"
    )


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evtq-"))["QueueUrl"]
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
    seen: list[Any] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            seen.append(body)
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s; saw {len(seen)} other message(s): {seen!r}")


def _poll_for_event(ctx, queue_url: str, match_fn, timeout_s: float) -> dict[str, Any] | None:
    """Like _wait_for_event_matching, but returns None on timeout instead of raising --
    used for the negative leg, where absence is the expected (asserted) outcome."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
