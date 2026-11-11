"""iam-role-missing-events-trust-rejected-for-rule-target."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-missing-events-trust-rejected-for-rule-target"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule target whose role does not trust events.amazonaws.com fails and dead-letters the
    event, while a sibling target on the same rule with a correctly-trusted role writes the
    record to Kinesis."""
    kinesis = ctx.client("kinesis")
    events = ctx.client("events")

    stream_name = ctx.unique_name("sim2real-bkp-stream-")
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)[
        "StreamDescriptionSummary"
    ]["StreamARN"]

    bad_role_arn = _create_role_with_trust(ctx, "ec2.amazonaws.com", stream_arn)
    good_role_arn = _create_role_with_trust(ctx, "events.amazonaws.com", stream_arn)

    rule_name = ctx.unique_name("sim2real-bkp-rule-")
    event_source = f"sim2real.test.{rule_name}"
    rule_arn = _create_rule(
        ctx, rule_name, {"source": [event_source], "detail-type": ["Backup Job State Change"]}
    )
    dlq_url, dlq_arn = _create_queue_for_rule(ctx, [rule_arn])

    _put_targets_with_retry(
        events,
        rule_name,
        [
            {
                "Id": "bad-target",
                "Arn": stream_arn,
                "RoleArn": bad_role_arn,
                "KinesisParameters": {"PartitionKeyPath": "$.detail-type"},
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
                "DeadLetterConfig": {"Arn": dlq_arn},
            },
            {
                "Id": "good-target",
                "Arn": stream_arn,
                "RoleArn": good_role_arn,
                "KinesisParameters": {"PartitionKeyPath": "$.detail-type"},
            },
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["bad-target", "good-target"]))

    shard_iterators = _latest_shard_iterators(kinesis, stream_name)

    marker = ctx.unique_name("job-")
    detail = json.dumps({"backupJobId": marker, "state": "COMPLETED"})

    # A single PutEvents does not reliably surface the DLQ delivery within a bounded window
    # (observed on real AWS), so the firing itself is retried -- each attempt is independently
    # a legitimate trigger of the same rule, and the loop stops as soon as both sides land.
    dlq_event: dict | None = None
    records: list = []
    for _ in range(4):
        put_resp = events.put_events(
            Entries=[{"Source": event_source, "DetailType": "Backup Job State Change", "Detail": detail}]
        )
        assert put_resp.get("FailedEntryCount", 0) == 0, f"PutEvents rejected the entry: {put_resp['Entries']}"
        if dlq_event is None:
            dlq_event = _poll_sqs_for_event(
                ctx, dlq_url, lambda d: d.get("detail", {}).get("backupJobId") == marker, timeout_s=30
            )
        if not records:
            records = _poll_kinesis_records(kinesis, shard_iterators, timeout_s=30)
        if dlq_event is not None and records:
            break
        time.sleep(2)

    assert dlq_event is not None, "the un-assumable-role target never landed on its DLQ"
    assert dlq_event["detail-type"] == "Backup Job State Change", (
        f"expected detail-type 'Backup Job State Change', got {dlq_event.get('detail-type')!r}"
    )
    assert dlq_event["detail"]["backupJobId"] == marker, (
        f"expected dead-lettered event for marker {marker!r}, got "
        f"{dlq_event.get('detail', {}).get('backupJobId')!r}"
    )

    assert len(records) >= 1, "target with a correctly trusted role should have been invoked"
    payloads = [json.loads(r["Data"]) for r in records]
    assert any(p.get("detail", {}).get("backupJobId") == marker for p in payloads), (
        f"expected a Kinesis record for marker {marker!r}, got backupJobIds="
        f"{[p.get('detail', {}).get('backupJobId') for p in payloads]}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_role_with_trust(ctx, principal_service: str, stream_arn: str) -> str:
    iam = ctx.client("iam")
    tag = principal_service.split(".")[0]
    name = ctx.unique_name(f"sim2real-bkp-role-{tag}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": principal_service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                    "Resource": stream_arn,
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=name, PolicyName="allow-kinesis-put", PolicyDocument=policy_doc)

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="allow-kinesis-put")
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _put_targets_with_retry(events, rule_name: str, targets: list[dict], timeout_s: float = 60.0) -> None:
    """IAM is eventually consistent: retry PutTargets until EventBridge accepts every entry
    rather than sleeping a fixed duration before the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_failure: Any = None
    while time.monotonic() < deadline:
        resp = events.put_targets(Rule=rule_name, Targets=targets)
        if resp.get("FailedEntryCount", 0) == 0:
            return
        last_failure = resp.get("FailedEntries")
        time.sleep(3.0)
    raise AssertionError(f"PutTargets never accepted every entry within {timeout_s}s: {last_failure}")


def _create_rule(ctx, name: str, pattern: dict[str, Any]) -> str:
    events = ctx.client("events")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return arn


def _create_queue_for_rule(ctx, rule_arns: list[str]) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-bkp-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    source_arn_condition = rule_arns[0] if len(rule_arns) == 1 else rule_arns
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn_condition}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _poll_sqs_for_event(ctx, queue_url: str, predicate, timeout_s: float = 60.0) -> dict | None:
    """Returns None on timeout; the caller decides whether that is retryable or terminal."""
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
    return None


def _latest_shard_iterators(kinesis, stream_name: str) -> list[str]:
    """An ON_DEMAND stream starts with several shards; the record could land on any of
    them depending on its partition key hash, so every shard needs its own iterator."""
    desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
    return [
        kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard["ShardId"], ShardIteratorType="LATEST"
        )["ShardIterator"]
        for shard in desc["Shards"]
    ]


def _poll_kinesis_records(kinesis, shard_iterators: list[str], timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    records: list[dict] = []
    iterators: list[str | None] = list(shard_iterators)
    while time.monotonic() < deadline and not records:
        next_iterators: list[str | None] = []
        for iterator in iterators:
            if iterator is None:
                continue
            resp = kinesis.get_records(ShardIterator=iterator, Limit=50)
            records.extend(resp.get("Records", []))
            next_iterators.append(resp.get("NextShardIterator"))
        iterators = next_iterators
        if not records:
            time.sleep(2)
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
