"""iam-role-trusts-events-service-enables-rule-target-invocation."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trusts-events-service-enables-rule-target-invocation"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Through a target RoleArn that trusts events.amazonaws.com, a CloudFront-shaped event put with PutEvents reaches
    the rule's Kinesis stream with its source and distributionId intact."""
    iam = ctx.client("iam")
    events = ctx.client("events")
    kinesis = ctx.client("kinesis")

    stream_name = ctx.unique_name("sim2real-cf-stream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(kinesis, stream_name)

    role_name = ctx.unique_name("sim2real-cf-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = role["Role"]["Arn"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="kinesis-put", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-put"))

    rule_name = ctx.unique_name("sim2real-cf-rule-")
    pattern = {"source": ["sim2real.cloudfront"], "detail-type": ["CloudFront Distribution Event (Simulated)"]}
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern))
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    target_id = "kinesis-target"
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": target_id, "Arn": stream_arn, "RoleArn": role_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    def _send() -> str:
        marker = ctx.unique_name("marker-")
        events.put_events(Entries=[{
            "Source": "sim2real.cloudfront",
            "DetailType": "CloudFront Distribution Event (Simulated)",
            "Detail": json.dumps({"distributionId": "EDFDVBD6EXAMPLE", "eventName": "CreateInvalidation", "marker": marker}),
        }])
        return marker

    # IAM role trust/policy propagation into EventBridge's target-invocation path
    # can lag tens of seconds after create_role/put_role_policy return, and a
    # single AssumeRole failure there is NOT retried by EventBridge itself — so
    # resend a fresh event (new marker) until one gets through.
    record, marker = _send_until_delivered(
        _send, lambda m: _wait_for_kinesis_record(kinesis, stream_name, m, timeout_s=20),
    )
    assert record is not None, "expected the matched event to reach the Kinesis stream via the trusted role"
    assert record["source"] == "sim2real.cloudfront", f"expected source 'sim2real.cloudfront', got {record['source']!r}"
    assert record["detail"]["distributionId"] == "EDFDVBD6EXAMPLE", (
        f"expected distributionId 'EDFDVBD6EXAMPLE' to survive delivery intact, got {record['detail'].get('distributionId')!r}"
    )


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
    deadline = time.monotonic() + timeout_s
    # A stream reported ACTIVE by describe_stream can still 404 on GetShardIterator for its
    # just-created shard for a brief window (shard-list propagation lags stream-status
    # propagation) -- bounded-retry the handshake instead of letting it raise once.
    iterator = None
    while time.monotonic() < deadline:
        try:
            shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]
            iterator = kinesis.get_shard_iterator(
                StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
            )["ShardIterator"]
            break
        except kinesis.exceptions.ResourceNotFoundException:
            time.sleep(2)
    if iterator is None:
        raise AssertionError(f"stream {stream_name} shard never became readable within {timeout_s}s")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
