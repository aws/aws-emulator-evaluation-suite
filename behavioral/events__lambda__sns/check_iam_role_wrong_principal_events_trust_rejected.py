"""iam-role-wrong-principal-events-trust-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-wrong-principal-events-trust-rejected"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:negative-delivery", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge cannot assume a role that trusts another principal: the event never reaches
    Kinesis and is dead-lettered with ERROR_CODE FAILED_TO_ASSUME_ROLE and the rule ARN, while a
    correctly trusted rule delivers."""
    iam = ctx.client("iam")
    events = ctx.client("events")
    kinesis = ctx.client("kinesis")
    sqs = ctx.client("sqs")

    stream_name = ctx.unique_name("sim2real-behav-pb-stream-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamARN"]

    dlq_name = ctx.unique_name("sim2real-behav-pb-dlq-")
    dlq_url = sqs.create_queue(QueueName=dlq_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    bus_name = ctx.unique_name("sim2real-behav-pb-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    good_role_name = ctx.unique_name("sim2real-behav-pb-good-role-")
    good_role_arn = _create_kinesis_role(ctx, iam, good_role_name, "events.amazonaws.com", stream_arn)
    bad_role_name = ctx.unique_name("sim2real-behav-pb-bad-role-")
    bad_role_arn = _create_kinesis_role(ctx, iam, bad_role_name, "s3.amazonaws.com", stream_arn)

    source = "sim2real.behav.permissionboundary"
    good_detail_type = ctx.unique_name("pb-good-")
    bad_detail_type = ctx.unique_name("pb-bad-")

    good_rule_name = ctx.unique_name("sim2real-behav-pb-good-rule-")
    events.put_rule(
        Name=good_rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [good_detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=good_rule_name, EventBusName=bus_name, Force=True))
    events.put_targets(
        Rule=good_rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "1", "Arn": stream_arn, "RoleArn": good_role_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=good_rule_name, EventBusName=bus_name, Ids=["1"], Force=True))

    bad_rule_name = ctx.unique_name("sim2real-behav-pb-bad-rule-")
    events.put_rule(
        Name=bad_rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [bad_detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=bad_rule_name, EventBusName=bus_name, Force=True))
    bad_rule_arn = events.describe_rule(Name=bad_rule_name, EventBusName=bus_name)["Arn"]

    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Dead-letter queue permissions",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": dlq_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": bad_rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"Policy": json.dumps(dlq_policy)})

    events.put_targets(
        Rule=bad_rule_name,
        EventBusName=bus_name,
        Targets=[{
            "Id": "1",
            "Arn": stream_arn,
            "RoleArn": bad_role_arn,
            "DeadLetterConfig": {"Arn": dlq_arn},
        }],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=bad_rule_name, EventBusName=bus_name, Ids=["1"], Force=True))

    _wait_for_role_readable(iam, good_role_name, timeout_s=60.0)
    _wait_for_role_readable(iam, bad_role_name, timeout_s=60.0)

    # A role just created is visible to the caller's own IAM reads immediately
    # (see _wait_for_role_readable above), but that says nothing about how soon
    # EventBridge's OWN internal AssumeRole path observes the trust document --
    # that propagation lag is not directly observable, so it is bounded by
    # retrying the actual thing under test (a fresh event, re-published) against
    # a deadline, rather than guessed with a fixed sleep.
    retry_start = time.monotonic()
    deadline = retry_start + 220.0
    good_marker = bad_marker = ""
    dlq_message: dict[str, Any] | None = None
    markers_seen: set[str] = set()
    attempts = 0
    while True:
        attempts += 1
        good_marker = ctx.unique_name("good-marker-")
        bad_marker = ctx.unique_name("bad-marker-")
        events.put_events(Entries=[
            {
                "EventBusName": bus_name, "Source": source, "DetailType": good_detail_type,
                "Detail": json.dumps({"marker": good_marker}),
            },
            {
                "EventBusName": bus_name, "Source": source, "DetailType": bad_detail_type,
                "Detail": json.dumps({"marker": bad_marker}),
            },
        ])
        remaining = max(deadline - time.monotonic(), 1.0)
        dlq_message = _poll_dlq(sqs, dlq_url, timeout_s=min(30.0, remaining))
        markers_seen |= _collect_kinesis_markers(kinesis, stream_name, timeout_s=min(30.0, remaining))
        if good_marker in markers_seen or time.monotonic() >= deadline:
            break

    assert good_marker in markers_seen, (
        f"positive control: the correctly-trusted role never delivered to Kinesis after "
        f"{attempts} attempt(s) over {time.monotonic() - retry_start:.0f}s"
    )
    assert dlq_message is not None, "the badly-trusted role's failed invocation never reached the DLQ"
    attrs = dlq_message["MessageAttributes"]
    error_code = attrs["ERROR_CODE"]["StringValue"]
    assert error_code == "FAILED_TO_ASSUME_ROLE", (
        f"expected the DLQ'd invocation failure to be attributed to FAILED_TO_ASSUME_ROLE, got {error_code!r}"
    )
    rule_arn_seen = attrs["RULE_ARN"]["StringValue"]
    assert rule_arn_seen == bad_rule_arn, (
        f"expected the DLQ message to attribute the failure to {bad_rule_arn!r}, got {rule_arn_seen!r}"
    )
    assert bad_marker not in markers_seen, "the wrongly-trusted role delivered to Kinesis despite the trust mismatch"


def _create_kinesis_role(ctx: Any, iam: Any, role_name: str, trust_service: str, stream_arn: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Per AWS's documented EventBridge->Kinesis role requirements, the statement uses
    # Resource "*" (not the stream ARN) -- EventBridge's internal PutRecord call for this
    # target type doesn't match a resource-scoped grant.
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
            "Resource": "*",
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="put-record", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="put-record"))
    return role_arn


def _wait_for_role_readable(iam: Any, role_name: str, timeout_s: float) -> None:
    """A role just created via CreateRole/PutRolePolicy is not instantly visible to every
    IAM read-path. Bound the wait on the caller's OWN view of the role and its inline
    policy, with a deadline and a stated reason, rather than a blind sleep -- a fast
    account isn't held back, and a slow one still fails loudly instead of racing."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            iam.get_role_policy(RoleName=role_name, PolicyName="put-record")
            return
        except iam.exceptions.NoSuchEntityException as exc:
            last_exc = exc
            time.sleep(2)
    raise AssertionError(
        f"role {role_name} and its inline policy never became visible to the caller within {timeout_s}s: {last_exc}"
    )


def _poll_dlq(sqs: Any, queue_url: str, timeout_s: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=10, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg
    return None


def _collect_kinesis_markers(kinesis: Any, stream_name: str, timeout_s: float) -> set[str]:
    shards = kinesis.list_shards(StreamName=stream_name)["Shards"]
    shard_id = shards[0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    markers: set[str] = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=50)
        for rec in resp.get("Records", []):
            try:
                data = json.loads(rec["Data"])
            except (ValueError, TypeError):
                continue
            # EventBridge writes the FULL event envelope to a Kinesis target (no
            # InputTransformer here), so the payload lands nested under "detail".
            marker = data.get("detail", {}).get("marker")
            if marker:
                markers.add(marker)
        iterator = resp.get("NextShardIterator")
        if iterator is None:
            break
        time.sleep(3)
    return markers


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
