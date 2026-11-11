"""e2e-log-group-subscription-destination-delivery-flow."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-log-group-subscription-destination-delivery-flow"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents -> subscription filter -> PutDestination(Kinesis) actually delivers the
    exact log payload to the Kinesis stream, end to end."""
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    log_group = ctx.unique_name("sim2real-behav-lg-")
    log_stream = ctx.unique_name("sim2real-behav-ls-")
    stream_name = ctx.unique_name("sim2real-behav-kds-")
    dest_name = ctx.unique_name("sim2real-behav-dest-")
    role_name = ctx.unique_name("sim2real-behav-role-")
    filter_name = ctx.unique_name("sim2real-behav-filt-")

    logs.create_log_group(
        logGroupName=log_group, tags={"sim2real-behav": "e2e-log-group-subscription-destination-delivery-flow"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real": "true"})
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(ctx, stream_name)
    stream_arn = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
        "StreamARN"
    ]

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    perm_policy = json.dumps(
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName="kinesis-write", PolicyDocument=perm_policy
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-write")
    )

    dest_arn = _put_destination_with_retry(ctx, dest_name, stream_arn, role_arn)
    ctx.on_cleanup(lambda: logs.delete_destination(destinationName=dest_name))

    # Even for an intra-account destination, CloudWatch Logs gates PutSubscriptionFilter on
    # the destination's resource-based access policy: without an explicit accessPolicy
    # authorizing this account, PutSubscriptionFilter is rejected with AccessDeniedException.
    dest_access_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "logs:PutSubscriptionFilter",
                    "Resource": dest_arn,
                }
            ],
        }
    )
    logs.put_destination_policy(destinationName=dest_name, accessPolicy=dest_access_policy)

    _put_subscription_filter_with_retry(
        ctx, log_group=log_group, filter_name=filter_name, dest_arn=dest_arn
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(
            logGroupName=log_group, filterName=filter_name
        )
    )

    marker = f"sim2real-marker-{uuid.uuid4().hex}"
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": now_ms, "message": marker}],
    )

    envelope = _poll_kinesis_for_envelope(ctx, stream_name, marker, timeout_s=120.0)
    assert envelope is not None, (
        f"marker {marker!r} was never delivered to the Kinesis destination stream"
    )
    # The delivered record is not just a bag of bytes containing the message text -- it is a
    # CloudWatch Logs subscription-filter envelope, and the destination-side identity fields in
    # that envelope must match this run's own resources exactly.
    assert envelope.get("messageType") == "DATA_MESSAGE", (
        f"expected messageType 'DATA_MESSAGE', got {envelope.get('messageType')!r}"
    )
    assert envelope.get("owner") == account_id, (
        f"expected envelope owner {account_id!r}, got {envelope.get('owner')!r}"
    )
    assert envelope.get("logGroup") == log_group, (
        f"expected envelope logGroup {log_group!r}, got {envelope.get('logGroup')!r}"
    )
    assert envelope.get("logStream") == log_stream, (
        f"expected envelope logStream {log_stream!r}, got {envelope.get('logStream')!r}"
    )
    assert filter_name in envelope.get("subscriptionFilters", []), (
        f"expected subscriptionFilters to include {filter_name!r}, "
        f"got {envelope.get('subscriptionFilters')!r}"
    )


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2.0)
    raise AssertionError(f"kinesis stream {stream_name} never became ACTIVE")


def _put_destination_with_retry(ctx, dest_name: str, stream_arn: str, role_arn: str) -> str:
    # newly created IAM role/policy is eventually consistent; PutDestination can transiently
    # reject the roleArn until the role has propagated.
    logs = ctx.client("logs")
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = logs.put_destination(
                destinationName=dest_name,
                targetArn=stream_arn,
                roleArn=role_arn,
                tags={"sim2real": "true"},
            )
            return resp["destination"]["arn"]
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"PutDestination never succeeded: {last_err}")


def _put_subscription_filter_with_retry(
    ctx, *, log_group: str, filter_name: str, dest_arn: str, timeout_s: float = 60.0
) -> None:
    # a just-written destination access policy can take a moment to propagate; retry past a
    # transient AccessDeniedException instead of treating it as fatal.
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=log_group,
                filterName=filter_name,
                filterPattern="",
                destinationArn=dest_arn,
            )
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"PutSubscriptionFilter never succeeded: {last_err}")



def _poll_kinesis_for_envelope(ctx, stream_name: str, marker: str, timeout_s: float) -> dict | None:
    kinesis = ctx.client("kinesis")
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][
        0
    ]["ShardId"]
    shard_iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=shard_iterator, Limit=100)
        shard_iterator = resp["NextShardIterator"]
        for record in resp.get("Records", []):
            try:
                payload = json.loads(gzip.decompress(record["Data"]))
            except (OSError, ValueError):
                continue
            for event in payload.get("logEvents", []):
                if event.get("message") == marker:
                    return payload
        time.sleep(2.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
