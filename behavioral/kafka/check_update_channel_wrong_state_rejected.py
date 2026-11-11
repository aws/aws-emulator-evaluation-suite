"""update-channel-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-channel-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel on a DELETING channel fails with BadRequestException and the exact state message and
    the channel is then gone, while the same update on an ACTIVE channel sets DataFreshnessInSeconds to
    900."""
    kafka = ctx.client("kafka")
    # Channels are only supported on Express clusters, which need three subnets in three AZs.
    net = ctx.network()
    subnet_ids, sg_id = net.subnet_ids[:3], net.security_group_id
    cluster_arn = _create_msk_cluster(ctx, ctx.unique_name("sim2real-kafka-chanst-"), subnet_ids, sg_id)

    topic_name = ctx.unique_name("sim2real-chanst-topic-")
    topic_arn = kafka.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=1
    )["TopicArn"]
    ctx.on_cleanup(lambda: _delete_topic_ignore(ctx, cluster_arn, topic_name))
    _wait_topic_active(ctx, cluster_arn, topic_name)

    bucket_arn, role_arn = _create_channel_destination(ctx)
    channel_to_delete = _create_channel(ctx, cluster_arn, topic_arn, bucket_arn, role_arn)
    channel_control = _create_channel(ctx, cluster_arn, topic_arn, bucket_arn, role_arn)

    kafka.delete_channel(ChannelArn=channel_to_delete, ClusterArn=cluster_arn)

    def _update_deleting():
        kafka.update_channel(
            ChannelArn=channel_to_delete,
            ClusterArn=cluster_arn,
            S3DestinationUpdate={"DataFreshnessInSeconds": 900},
        )

    # Race the update against the DELETING transition: retry briefly on a stray
    # success (SG/API race) but stop the instant we see a rejection or the channel
    # has fully disappeared.
    code, message = "pending", None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        code, message = _refusal(_update_deleting)
        if code != "ok":
            break
        try:
            described = kafka.describe_channel(ChannelArn=channel_to_delete, ClusterArn=cluster_arn)
            if described["Status"] not in ("DELETING",):
                break
        except ClientError:
            break
        time.sleep(2)

    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Channel cannot be updated in state DELETING. Channel must be in ACTIVE state to be updated.", (
        f"UpdateChannel rejection message: {message!r}"
    )

    # Effect absent: the update never took hold -- the channel proceeds to disappear.
    gone = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            kafka.describe_channel(ChannelArn=channel_to_delete, ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                gone = True
                break
        time.sleep(5)
    assert gone, "expected the deleting channel to eventually disappear"

    # Positive control: the identical update succeeds on the ACTIVE control channel.
    kafka.update_channel(
        ChannelArn=channel_control,
        ClusterArn=cluster_arn,
        S3DestinationUpdate={"DataFreshnessInSeconds": 900},
    )
    # The update applies asynchronously, so poll (bounded) for the channel to be ACTIVE with it.
    deadline = time.monotonic() + 600
    while True:
        described_control = kafka.describe_channel(ChannelArn=channel_control, ClusterArn=cluster_arn)
        if (described_control["Status"] == "ACTIVE"
                and described_control["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == 900):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert described_control["Status"] == "ACTIVE", (
        f"the control channel did not return to ACTIVE after UpdateChannel: {described_control['Status']!r}"
    )
    assert described_control["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == 900


def _create_msk_cluster(ctx, name, subnet_ids, sg_id, *, num_brokers=None):
    """A three-broker Express cluster: CreateChannel answers "Channels are only supported on
    Amazon MSK Express clusters" for a Standard one. Express brokers accept
    Kafka 3.8.x, and Express instance types are accepted only through CreateClusterV2."""
    kafka = ctx.client("kafka")
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.8.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.8.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "KafkaVersion": "3.8.x",
            "NumberOfBrokerNodes": num_brokers or len(subnet_ids),
            "BrokerNodeGroupInfo": {
                "InstanceType": "express.m7g.large",
                "ClientSubnets": subnet_ids,
                "SecurityGroups": [sg_id],
            },
        },
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_ignore(ctx, arn))
    # An Express cluster can stay in CREATING past 1800 s.
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=3000, interval_s=20)
    return arn


def _delete_cluster_ignore(ctx, arn):
    """Deletes the cluster and waits until it is gone; a cluster still present raises."""
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(20)
    raise AssertionError(f"cluster {arn} still present 900s after DeleteCluster")


def _delete_topic_ignore(ctx, cluster_arn, topic_name):
    try:
        ctx.client("kafka").delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_cluster_state(ctx, arn, ok_states, *, timeout_s, interval_s):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in ok_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {ok_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {ok_states} within {timeout_s}s (last state={last})")


def _wait_topic_active(ctx, cluster_arn, topic_name, *, timeout_s=300, interval_s=5):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except ClientError as err:
            # The topic APIs "reflect data that updates approximately every minute"
            # (https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-topics.html).
            if err.response["Error"]["Code"] != "NotFoundException":
                raise
            last = "NotFound"
            time.sleep(interval_s)
            continue
        last = resp["Status"]
        if last == "ACTIVE":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached ACTIVE (last={last})")


def _create_channel_destination(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket_name = ctx.unique_name("sim2real-kafka-chanst-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket_ignore(ctx, bucket_name))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    role_name = ctx.unique_name("sim2real-kafka-chanst-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    return bucket_arn, role_arn


def _create_channel(ctx, cluster_arn, topic_arn, bucket_arn, role_arn):
    kafka = ctx.client("kafka")
    channel_name = ctx.unique_name("sim2real-channel-")
    # Each channel needs its own S3 destination: CreateChannel refuses a bucket and output prefix
    # "already in use by another channel in this cluster".
    resp = _when_channel_ready(lambda: kafka.create_channel(
        ChannelName=channel_name,
        ClusterArn=cluster_arn,
        TopicConfigurationList=[
            {"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "BYTE_ARRAY"}}
        ],
        S3DestinationConfiguration={
            "ServiceExecutionRoleArn": role_arn,
            "Storage": {
                "BucketArn": bucket_arn,
                "CompressionType": "NONE",
                "StorageClass": "STANDARD",
                "OutputPrefix": f"data/{channel_name}/",
            },
            "DeadLetterQueueS3": {"BucketArn": bucket_arn, "ErrorOutputPrefix": f"dlq/{channel_name}/"},
        },
    ))
    channel_arn = resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel_ignore(ctx, cluster_arn, channel_arn))
    _wait_channel_status(ctx, cluster_arn, channel_arn, {"ACTIVE"})
    return channel_arn


def _when_channel_ready(call, timeout_s=300.0, interval_s=15.0):
    """CreateChannel answered BadRequestException "Topic ... does not exist" for an ACTIVE topic on
    real AWS while the channel service had not yet seen it, and ForbiddenException "Unable to assume
    the channel's service execution role" for a just-created role; both are readiness, so they
    are retried, bounded. Anything else returns."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as err:
            message = err.response["Error"].get("Message", "").lower()
            readiness = err.response["Error"]["Code"] in ("BadRequestException", "ForbiddenException") and (
                "does not exist" in message or "assume" in message
            )
            if not readiness or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_channel_ignore(ctx, cluster_arn, channel_arn):
    """Deletes the channel and waits until it is gone, so the topic and cluster deletes after it
    can proceed; a channel still present raises."""
    kafka = ctx.client("kafka")
    try:
        kafka.delete_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"channel {channel_arn} still present 600s after DeleteChannel")


def _delete_bucket_ignore(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket_name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role_ignore(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _wait_channel_status(ctx, cluster_arn, channel_arn, ok_statuses, *, timeout_s=900, interval_s=10):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
        last = resp["Status"]
        if last in ok_statuses:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_arn} never reached {ok_statuses} (last={last})")


def _refusal(fn):
    """(code, message) of the ClientError fn raises; ("ok", None) while the call still succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return "ok", None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
