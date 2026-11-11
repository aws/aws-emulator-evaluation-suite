"""iam-role-trusts-events-service-assumed."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trusts-events-service-assumed"
GROUP = "trust-policy"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge assumes a role trusting events.amazonaws.com to deliver to a Kinesis stream
    target that requires RoleArn: the event's record lands on the stream."""
    iam = ctx.client("iam")
    events = ctx.client("events")
    kinesis = ctx.client("kinesis")

    stream_name = ctx.unique_name("sim2real-behav-tp-stream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamARN"]

    role_name = ctx.unique_name("sim2real-behav-tp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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

    bus_name = ctx.unique_name("sim2real-behav-tp-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("sim2real-behav-tp-rule-")
    source = "sim2real.behav.trustpolicy"
    detail_type = ctx.unique_name("trust-policy-event-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name, Force=True))
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "1", "Arn": stream_arn, "RoleArn": role_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["1"], Force=True))

    # A role just created via CreateRole/PutRolePolicy is not instantly visible to every
    # IAM read-path, and PutTargets does not synchronously verify the role is assumable
    # (unlike Lambda's CreateFunction) -- EventBridge only finds out at invocation time. So
    # instead of a blind pre-sleep, re-issue PutEvents on a bounded retry: an early attempt
    # that loses the propagation race is not wasted, it is just a retry with a fresh marker.
    _put_events_until_delivered(
        events, kinesis, bus_name, source, detail_type, stream_name, ctx, timeout_s=150.0, retry_interval_s=15.0,
    )


def _poll_kinesis_for_marker(kinesis: Any, stream_name: str, marker: str, timeout_s: float) -> bool:
    shards = kinesis.list_shards(StreamName=stream_name)["Shards"]
    shard_id = shards[0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=50)
        for rec in resp.get("Records", []):
            try:
                data = json.loads(rec["Data"])
            except (ValueError, TypeError):
                continue
            # EventBridge writes the FULL event envelope to a Kinesis target (no
            # InputTransformer here), so the payload we put_events with lands nested
            # under "detail", not at the record's top level.
            if data.get("detail", {}).get("marker") == marker:
                return True
        iterator = resp.get("NextShardIterator")
        if iterator is None:
            break
        time.sleep(3)
    return False


def _put_events_until_delivered(
    events: Any,
    kinesis: Any,
    bus_name: str,
    source: str,
    detail_type: str,
    stream_name: str,
    ctx: Any,
    timeout_s: float,
    retry_interval_s: float,
) -> str:
    deadline = time.monotonic() + timeout_s
    last_marker = ""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        last_marker = ctx.unique_name("marker-")
        events.put_events(Entries=[{
            "EventBusName": bus_name,
            "Source": source,
            "DetailType": detail_type,
            "Detail": json.dumps({"marker": last_marker}),
        }])
        if _poll_kinesis_for_marker(kinesis, stream_name, last_marker, timeout_s=min(retry_interval_s, remaining)):
            return last_marker
    raise AssertionError(
        f"marker {last_marker!r} never appeared on Kinesis stream {stream_name} within the poll "
        "budget -- the events.amazonaws.com-trusted role was never actually assumed by EventBridge"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
