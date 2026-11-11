"""channel-create-invalid-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-create-invalid-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]

# Prefix of the failure raised when a resource never reaches its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel with a DataFreshnessInSeconds outside the documented 300-900s range
    fails validation (BadRequestException) instead of silently creating a broken channel,
    while an otherwise-identical valid request succeeds (positive control)."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_express_cluster(ctx)
    role_arn, bucket = _create_channel_role_and_bucket(ctx)
    topic_arn = _create_channel_topic(ctx, cluster_arn)

    bad_name = ctx.unique_name("sim2real-badchan-")
    code, message = _error_of(
        lambda: _when_channel_ready(lambda: kafka.create_channel(
            ClusterArn=cluster_arn,
            ChannelName=bad_name,
            TopicConfigurationList=[{"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "JSON"}}],
            S3DestinationConfiguration={
                "ServiceExecutionRoleArn": role_arn,
                "DataFreshnessInSeconds": 1,  # outside the documented 300-900 range
                "DeadLetterQueueS3": {"BucketArn": f"arn:aws:s3:::{bucket}", "ErrorOutputPrefix": "dlq/"},
                "Storage": {
                    "BucketArn": f"arn:aws:s3:::{bucket}",
                    "OutputPrefix": "data/",
                    "StorageClass": "STANDARD",
                    "CompressionType": "NONE",
                },
            },
        ))
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    # A readiness refusal that outlasted _when_channel_ready is a BadRequestException too; it
    # says nothing about DataFreshnessInSeconds.
    assert "does not exist" not in message.lower() and "assume" not in message.lower(), (
        f"CreateChannel was refused for readiness, not for DataFreshnessInSeconds=1: {message!r}"
    )
    assert message == "Data freshness must be between 300 and 900 seconds.", f"rejection message: {message!r}"

    channels = kafka.list_channels(ClusterArn=cluster_arn).get("Channels", [])
    assert bad_name not in [c["ChannelName"] for c in channels], "invalid channel must not have been created"

    # Positive control: the identical request with a valid DataFreshnessInSeconds succeeds.
    good_name = ctx.unique_name("sim2real-goodchan-")
    resp = _when_channel_ready(lambda: kafka.create_channel(
        ClusterArn=cluster_arn,
        ChannelName=good_name,
        TopicConfigurationList=[{"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "JSON"}}],
        S3DestinationConfiguration={
            "ServiceExecutionRoleArn": role_arn,
            "DataFreshnessInSeconds": 300,
            "DeadLetterQueueS3": {"BucketArn": f"arn:aws:s3:::{bucket}", "ErrorOutputPrefix": "dlq/"},
            "Storage": {
                "BucketArn": f"arn:aws:s3:::{bucket}",
                "OutputPrefix": "data/",
                "StorageClass": "STANDARD",
                "CompressionType": "NONE",
            },
        },
    ))
    good_arn = resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel_ignore_missing(ctx, cluster_arn, good_arn))
    described = _wait_channel_status(ctx, cluster_arn, good_arn, {"ACTIVE"}, timeout_s=900)
    assert described["Status"] == "ACTIVE", f"expected ACTIVE, got {described.get('Status')}"


# ===== helpers =====

def _error_of(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return True
        raise
    return False


def _wait_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if last_state in target_states:
            return last_state
        time.sleep(interval_s)
    raise _never_ready(
        f"cluster did not reach {target_states} within {timeout_s}s (last state={last_state})",
    )


def _create_express_cluster(ctx, timeout_s=3600):
    kafka = ctx.client("kafka")
    subnets = ctx.network().subnet_ids[:3]
    # Express brokers accept Kafka 3.8.x ("Valid values: [3.8.x, 3.9.x.kraft, 4.2.x.kraft]",
    # observed on real AWS), and Express instance types are accepted only by CreateClusterV2.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.8.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.8.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=ctx.unique_name("sim2real-mskx-"),
        Provisioned={
            "KafkaVersion": "3.8.x",
            "NumberOfBrokerNodes": 3,
            "BrokerNodeGroupInfo": {
                # Express brokers manage their own storage; CreateClusterV2 rejects
                # StorageInfo for this instance family with a BadRequestException.
                "InstanceType": "express.m7g.large",
                "ClientSubnets": subnets,
            },
        },
    )["ClusterArn"]

    def _cleanup():
        # DeleteCluster is refused while a channel operation keeps the cluster UPDATING, so let it
        # settle first (bounded: if it does not, the delete below reports the refusal).
        try:
            _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=300)
        except AssertionError:
            pass
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if _gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
                return
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still present 900s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_channel_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-msk-chan-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-msk-chan-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-msk-chan-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn, bucket


def _delete_topic_ignore_missing(ctx, cluster_arn, topic_name):
    kafka = ctx.client("kafka")
    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "UnknownTopicOrPartitionException"):
            raise


def _create_channel_topic(ctx, cluster_arn):
    """A topic CreateChannel can use: CreateTopic returns while the topic is CREATING, and the
    topic APIs "reflect data that updates approximately every minute"
    (https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-topics.html), so this
    waits (bounded) until DescribeTopic reports it ACTIVE."""
    kafka = ctx.client("kafka")
    topic_name = ctx.unique_name("sim2real-chantopic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=3)
    ctx.on_cleanup(lambda: _delete_topic_ignore_missing(ctx, cluster_arn, topic_name))
    deadline = time.monotonic() + 300
    info = {}
    while time.monotonic() < deadline:
        try:
            info = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
            info = {}
        if info.get("Status") == "ACTIVE" and info.get("TopicArn"):
            return info["TopicArn"]
        time.sleep(2)
    raise AssertionError(f"topic {topic_name} never reached ACTIVE within 300s (last {info.get('Status')!r})")


def _when_channel_ready(call, timeout_s=300.0, interval_s=15.0):
    """CreateChannel answered BadRequestException "Topic ... does not exist" for an ACTIVE topic on
    real AWS while the channel service had not yet seen it, and a just-created service role may not
    be assumable yet; both are readiness, so they are retried, bounded. Anything else returns."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as e:
            message = e.response["Error"].get("Message", "").lower()
            readiness = e.response["Error"]["Code"] == "BadRequestException" and (
                "does not exist" in message or "assume" in message
            )
            if not readiness or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_channel_ignore_missing(ctx, cluster_arn, channel_arn, timeout_s=900.0):
    """Deletes the channel and waits until it is gone, so the topic and cluster deletes after it
    can proceed; a channel still present at the deadline raises."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    # DeleteChannel is refused while the channel is CREATING ("Channel must be in ACTIVE, FAILED,
    # or SUSPENDED state to be deleted", observed on real AWS), so it is let settle first.
    while time.monotonic() < deadline:
        try:
            status = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn).get("Status")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if status in ("ACTIVE", "FAILED", "SUSPENDED", "DELETING"):
            break
        time.sleep(10)
    try:
        kafka.delete_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    while time.monotonic() < deadline:
        if _gone(lambda: kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)):
            return
        time.sleep(10)
    raise AssertionError(f"channel {channel_arn} still present {timeout_s}s after DeleteChannel")


def _wait_channel_status(ctx, cluster_arn, channel_arn, target_statuses, timeout_s=900, interval_s=10):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
        if last.get("Status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise _never_ready(f"channel {channel_arn} never reached {target_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
