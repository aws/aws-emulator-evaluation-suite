"""iam-role-trust-scoped-with-external-condition-enforced."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-scoped-with-external-condition-enforced"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A trust policy scoped by aws:SourceArn to one rule refuses another rule using the same role: its event lands on
    the DLQ with FAILED_TO_ASSUME_ROLE and never reaches the target, while the rule named in the condition delivers."""
    iam = ctx.client("iam")
    events = ctx.client("events")
    kinesis = ctx.client("kinesis")
    sqs = ctx.client("sqs")

    stream_name = ctx.unique_name("sim2real-scoped-stream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(kinesis, stream_name)

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-scoped-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rule_a_name = ctx.unique_name("sim2real-scoped-rule-a-")
    pattern_a = {"source": ["sim2real.scoped"], "detail-type": ["Scoped-Test-A"]}
    rule_a_arn = events.put_rule(Name=rule_a_name, EventPattern=json.dumps(pattern_a))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_a_name))

    rule_b_name = ctx.unique_name("sim2real-scoped-rule-b-")
    pattern_b = {"source": ["sim2real.scoped"], "detail-type": ["Scoped-Test-B"]}
    rule_b_arn = events.put_rule(Name=rule_b_name, EventPattern=json.dumps(pattern_b))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_b_name))

    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": [rule_a_arn, rule_b_arn]}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(dlq_policy)})

    role_name = ctx.unique_name("sim2real-scoped-role-")
    scoped_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_a_arn}},
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(scoped_trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    kinesis_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="kinesis-put", PolicyDocument=json.dumps(kinesis_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-put"))

    target_id = "kinesis-target"
    retry_policy = {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}

    # Attach the role -- scoped to rule A's ARN -- as the RoleArn for rule B (mismatch).
    events.put_targets(
        Rule=rule_b_name,
        Targets=[{
            "Id": target_id, "Arn": stream_arn, "RoleArn": role_arn,
            "RetryPolicy": retry_policy, "DeadLetterConfig": {"Arn": queue_arn},
        }],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_b_name, Ids=[target_id]))

    marker_mismatch = ctx.unique_name("marker-mismatch-")
    events.put_events(Entries=[{
        "Source": "sim2real.scoped",
        "DetailType": "Scoped-Test-B",
        "Detail": json.dumps({"marker": marker_mismatch}),
    }])

    dlq_msg = _wait_for_dlq_message(sqs, queue_url, marker_mismatch, timeout_s=120)
    assert dlq_msg is not None, "expected rule B's invocation (wrong SourceArn) to fail and land on the DLQ"
    assert dlq_msg["ERROR_CODE"] == "FAILED_TO_ASSUME_ROLE", (
        f"expected FAILED_TO_ASSUME_ROLE for the SourceArn-mismatched invocation, got {dlq_msg['ERROR_CODE']!r}"
    )
    record = _wait_for_kinesis_record(kinesis, stream_name, marker_mismatch, timeout_s=20)
    assert record is None, "target must never receive the event when the trust condition's SourceArn doesn't match"

    # Same role attached to rule A (the ARN the condition actually names) must succeed.
    events.put_targets(
        Rule=rule_a_name,
        Targets=[{"Id": target_id, "Arn": stream_arn, "RoleArn": role_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_a_name, Ids=[target_id]))

    marker_match = ctx.unique_name("marker-match-")
    events.put_events(Entries=[{
        "Source": "sim2real.scoped",
        "DetailType": "Scoped-Test-A",
        "Detail": json.dumps({"marker": marker_match}),
    }])
    good_record = _wait_for_kinesis_record(kinesis, stream_name, marker_match, timeout_s=120)
    assert good_record is not None, "invocation from the rule named in the trust condition must succeed"


def _wait_stream_active(kinesis: Any, stream_name: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _get_shard_iterator(kinesis: Any, stream_name: str, deadline: float) -> str:
    # A stream that just reported ACTIVE can still 404 on GetShardIterator for a brief
    # window -- the shard's data-plane record lags the control-plane status -- so this
    # is a bounded retry, not a single shot.
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]
            return kinesis.get_shard_iterator(
                StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
            )["ShardIterator"]
        except kinesis.exceptions.ResourceNotFoundException as e:
            last_err = e
            time.sleep(1)
    raise AssertionError(f"stream {stream_name} never exposed a readable shard iterator: {last_err}")


def _wait_for_kinesis_record(kinesis: Any, stream_name: str, marker: str, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    iterator = _get_shard_iterator(kinesis, stream_name, deadline)
    while time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=50)
        for rec in resp["Records"]:
            try:
                payload = json.loads(rec["Data"])
            except (ValueError, TypeError):
                continue
            if payload.get("detail", {}).get("marker") == marker:
                return payload
        iterator = resp["NextShardIterator"]
        time.sleep(2)
    return None


def _wait_for_dlq_message(sqs: Any, queue_url: str, marker: str, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (ValueError, TypeError):
                body = {}
            if body.get("detail", {}).get("marker") == marker:
                attrs = {k: v["StringValue"] for k, v in msg.get("MessageAttributes", {}).items()}
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return attrs
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
