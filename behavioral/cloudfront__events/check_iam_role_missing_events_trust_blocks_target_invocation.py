"""iam-role-missing-events-trust-blocks-target-invocation."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-missing-events-trust-blocks-target-invocation"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With a target RoleArn that trusts only lambda.amazonaws.com, a matched event lands on the DLQ with
    FAILED_TO_ASSUME_ROLE and never reaches the Kinesis stream; with a role that trusts events.amazonaws.com on the
    same rule and stream, the event is delivered."""
    iam = ctx.client("iam")
    events = ctx.client("events")
    kinesis = ctx.client("kinesis")
    sqs = ctx.client("sqs")

    tag = {"sim2real-check": CHECK}

    stream_name = ctx.unique_name("sim2real-notrust-stream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags=tag)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(kinesis, stream_name)

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-notrust-dlq-"), tags=tag)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-notrust-rule-")
    pattern = {"source": ["sim2real.notrust"], "detail-type": ["Notrust Test Event"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(dlq_policy)})

    bad_role_name = ctx.unique_name("sim2real-notrust-badrole-")
    bad_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(bad_trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    kinesis_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=bad_role_name, PolicyName="kinesis-put", PolicyDocument=json.dumps(kinesis_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName="kinesis-put"))

    target_id = "kinesis-target"
    events.put_targets(
        Rule=rule_name,
        Targets=[{
            "Id": target_id,
            "Arn": stream_arn,
            "RoleArn": bad_role_arn,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": queue_arn},
        }],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    def _send_bad() -> str:
        m = ctx.unique_name("marker-bad-")
        events.put_events(Entries=[{
            "Source": "sim2real.notrust",
            "DetailType": "Notrust Test Event",
            "Detail": json.dumps({"marker": m}),
        }])
        return m

    # The DLQ's resource policy (granting events.amazonaws.com sqs:SendMessage)
    # can also take a little time to propagate; resend fresh events (new
    # marker) until the failure is actually observed on the DLQ.
    dlq_msg, marker_bad = _send_until_delivered(
        _send_bad, lambda m: _wait_for_dlq_message(sqs, queue_url, m, timeout_s=20),
    )
    assert dlq_msg is not None, "expected the failed invocation to land on the DLQ"
    error_code = dlq_msg["ERROR_CODE"]
    assert error_code == "FAILED_TO_ASSUME_ROLE", f"expected FAILED_TO_ASSUME_ROLE, got {error_code!r}"

    record = _wait_for_kinesis_record(kinesis, stream_name, marker_bad, timeout_s=20)
    assert record is None, "target must never have received the event with the untrusted role"

    # positive control: same rule/target/stream, now with a role events.amazonaws.com can assume
    good_role_name = ctx.unique_name("sim2real-notrust-goodrole-")
    good_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    good_role_arn = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(good_trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.put_role_policy(RoleName=good_role_name, PolicyName="kinesis-put", PolicyDocument=json.dumps(kinesis_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName="kinesis-put"))

    events.put_targets(
        Rule=rule_name,
        Targets=[{
            "Id": target_id,
            "Arn": stream_arn,
            "RoleArn": good_role_arn,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": queue_arn},
        }],
    )
    marker_good = ctx.unique_name("marker-good-")

    def _send_good() -> str:
        m = ctx.unique_name("marker-good-")
        events.put_events(Entries=[{
            "Source": "sim2real.notrust",
            "DetailType": "Notrust Test Event",
            "Detail": json.dumps({"marker": m}),
        }])
        return m

    # IAM role trust/policy propagation into EventBridge's target-invocation path
    # can lag tens of seconds after create_role/put_role_policy return, and a
    # single AssumeRole failure there is NOT retried by EventBridge itself — so
    # resend a fresh event (new marker) until one gets through.
    good_record, marker_good = _send_until_delivered(
        _send_good, lambda m: _wait_for_kinesis_record(kinesis, stream_name, m, timeout_s=20),
    )
    assert good_record is not None, "positive control with a correctly-trusted role must succeed"


def _wait_stream_active(kinesis: Any, stream_name: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _send_until_delivered(send_fn: Any, poll_fn: Any, overall_timeout_s: float = 180.0, retry_gap_s: float = 5.0):
    deadline = time.monotonic() + overall_timeout_s
    last_marker = None
    while time.monotonic() < deadline:
        last_marker = send_fn()
        result = poll_fn(last_marker)
        if result is not None:
            return result, last_marker
        time.sleep(retry_gap_s)
    return None, last_marker


def _wait_for_kinesis_record(kinesis: Any, stream_name: str, marker: str, timeout_s: float = 120.0):
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    deadline = time.monotonic() + timeout_s
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
