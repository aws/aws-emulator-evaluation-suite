"""channel-create-duplicate-name-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-create-duplicate-name-conflict"
GROUP = "concurrency"
SERVICES = ["kafka"]

# A CONTROL-PLANE convergence FAIL marker.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateChannel calls with the identical ChannelName on the same cluster
    race to a single winner; the loser is refused with BadRequestException (what real AWS
    answers, not ConflictException) and only one channel exists."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_express_cluster(ctx)
    role_arn, bucket = _create_channel_role_and_bucket(ctx)
    topic_arn = _create_channel_topic(ctx, cluster_arn)
    channel_name = ctx.unique_name("sim2real-dupchan-")

    def _attempt():
        try:
            resp = kafka.create_channel(
                ClusterArn=cluster_arn,
                ChannelName=channel_name,
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
            )
            return ("ok", resp["ChannelArn"])
        except ClientError as e:
            message = e.response["Error"].get("Message", "").lower()
            if e.response["Error"]["Code"] in ("BadRequestException", "ForbiddenException") and (
                "does not exist" in message or "assume" in message
            ):
                return ("not-ready", message)
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    # The channel service can answer "Topic ... does not exist" for a topic that is already ACTIVE,
    # and a just-created role may not be assumable yet (see _when_channel_ready). A race in which
    # both calls hit that readiness refusal decided nothing about the name, so it is run again,
    # bounded; the first race that gets past readiness is the one graded. A race in which only one
    # call got past readiness did not contend for the name and fails the one-loser assertion below
    # rather than being run again: a second race would only meet the channel the first created.
    deadline = time.monotonic() + (300 if ctx.time_left() is None else min(300, ctx.time_left()))
    while True:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: _attempt(), range(2)))
        if any(r[0] != "not-ready" for r in results):
            break
        if time.monotonic() >= deadline:
            raise _never_ready(f"CreateChannel never got past readiness within 300s: {results}")
        time.sleep(2)

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]
    assert len(winners) == 1, f"expected exactly one winning CreateChannel, got {winners}"
    assert len(losers) == 1, f"expected exactly one losing CreateChannel, got {losers}"
    assert losers[0][1] == "BadRequestException", f"expected BadRequestException for the loser, got {losers[0][1]}"
    assert losers[0][2] == f"A channel with name '{channel_name}' already exists for this cluster.", (
        f"loser's rejection message: {losers[0][2]!r}"
    )

    channel_arn = winners[0][1]
    ctx.on_cleanup(lambda: _delete_channel_ignore_missing(ctx, cluster_arn, channel_arn))

    channels = kafka.list_channels(ClusterArn=cluster_arn).get("Channels", [])
    matching = [c for c in channels if c["ChannelName"] == channel_name]
    assert len(matching) == 1, f"expected exactly one channel named {channel_name}, found {len(matching)}"
    assert matching[0]["ChannelArn"] == channel_arn


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
    # Express brokers accept Kafka 3.8.x (CreateClusterV2's rejection lists "Valid values:
    # [3.8.x, 3.9.x.kraft, 4.2.x.kraft]"), and Express instance types are accepted only by
    # CreateClusterV2.
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
    deadline = time.monotonic() + (300 if ctx.time_left() is None else min(300, ctx.time_left()))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
