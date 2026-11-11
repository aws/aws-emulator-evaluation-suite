"""channel-describe-after-delete-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-describe-after-delete-not-found"
GROUP = "state-machine"
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
    """DescribeChannel on a deleted channel id fails with NotFoundException instead of
    returning stale cached data, while a still-live sibling channel keeps describing fine."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_express_cluster(ctx)
    role_arn, bucket = _create_channel_role_and_bucket(ctx)
    topic_arn = _create_channel_topic(ctx, cluster_arn)

    doomed_arn = _create_channel(ctx, cluster_arn, role_arn, bucket, topic_arn)
    ctx.on_cleanup(lambda: _delete_channel_ignore_missing(ctx, cluster_arn, doomed_arn))
    survivor_arn = _create_channel(ctx, cluster_arn, role_arn, bucket, topic_arn)
    ctx.on_cleanup(lambda: _delete_channel_ignore_missing(ctx, cluster_arn, survivor_arn))

    _wait_channel_status(ctx, cluster_arn, doomed_arn, {"ACTIVE"}, timeout_s=900)
    _wait_channel_status(ctx, cluster_arn, survivor_arn, {"ACTIVE"}, timeout_s=900)

    kafka.delete_channel(ClusterArn=cluster_arn, ChannelArn=doomed_arn)
    deadline = time.monotonic() + 300
    code = message = None
    while time.monotonic() < deadline:
        try:
            kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=doomed_arn)
            code = message = None
        except ClientError as e:
            code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
            if code == "NotFoundException":
                break
        time.sleep(2)
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "The requested resource doesn\u2019t exist.", f"DescribeChannel message: {message!r}"

    # The surviving channel must still describe normally (no cross-contamination from the delete).
    survivor = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=survivor_arn)
    assert survivor["Status"] == "ACTIVE"
    assert survivor["ChannelArn"] == survivor_arn


# ===== helpers =====

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
    # A 3-broker Express cluster can take over 40 minutes to reach ACTIVE on AWS, so the
    # default deadline is an hour.
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


def _delete_topic_ignore_missing(ctx, cluster_arn, topic_name, timeout_s=300.0):
    """DeleteTopic is refused while the topic "has associated Channels", which can outlast the
    channel's own NotFound by a while, so that refusal is retried until the deadline."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NotFoundException", "UnknownTopicOrPartitionException"):
                return
            held = "associated Channels" in e.response["Error"].get("Message", "")
            if not held or time.monotonic() >= deadline:
                raise
        time.sleep(10)


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


def _create_channel(ctx, cluster_arn, role_arn, bucket, topic_arn):
    kafka = ctx.client("kafka")
    channel_name = ctx.unique_name("sim2real-channel-")
    # Each channel needs its own S3 destination: CreateChannel refuses a bucket and output prefix
    # "already in use by another channel in this cluster" (observed on real AWS).
    resp = _when_channel_ready(lambda: kafka.create_channel(
        ClusterArn=cluster_arn,
        ChannelName=channel_name,
        TopicConfigurationList=[{"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "JSON"}}],
        S3DestinationConfiguration={
            "ServiceExecutionRoleArn": role_arn,
            "DataFreshnessInSeconds": 300,
            "DeadLetterQueueS3": {"BucketArn": f"arn:aws:s3:::{bucket}", "ErrorOutputPrefix": f"dlq/{channel_name}/"},
            "Storage": {
                "BucketArn": f"arn:aws:s3:::{bucket}",
                "OutputPrefix": f"data/{channel_name}/",
                "StorageClass": "STANDARD",
                "CompressionType": "NONE",
            },
        },
    ))
    return resp["ChannelArn"]


def _delete_channel_ignore_missing(ctx, cluster_arn, channel_arn, timeout_s=600.0):
    """Deletes the channel and waits until it is gone, so the topic and cluster deletes after it
    can proceed; a channel still present at the deadline raises."""
    kafka = ctx.client("kafka")
    try:
        kafka.delete_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
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
    raise AssertionError(f"channel {channel_arn} never reached {target_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
