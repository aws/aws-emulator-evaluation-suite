"""channel-update-mutation-reflected-in-describe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "channel-update-mutation-reflected-in-describe"
GROUP = "state-machine"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A successful UpdateChannel call changes the field DescribeChannel and ListChannels
    return, not merely the (near-empty) UpdateChannel response echo."""
    # Express instance types require 3 client subnets in distinct AZs (CreateClusterV2 refuses
    # fewer: "Clusters with Express instance types require 3 subnets.").
    cluster_arn, _subnets, _sg = _create_provisioned_cluster(ctx, num_brokers=3)
    topic_name = _create_topic(ctx, cluster_arn)
    kafka = ctx.client("kafka")
    topic_arn = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)["TopicArn"]
    bucket = _create_bucket(ctx)
    role_arn = _create_channel_role(ctx, bucket)

    channel_name = ctx.unique_name("sim2real-behav-chan-")
    create_resp = _retry_until(
        lambda: kafka.create_channel(
            ChannelName=channel_name,
            ClusterArn=cluster_arn,
            TopicConfigurationList=[
                {"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "BYTE_ARRAY"}}
            ],
            S3DestinationConfiguration={
                "DataFreshnessInSeconds": 600,
                "ServiceExecutionRoleArn": role_arn,
                "Storage": {
                    "BucketArn": f"arn:aws:s3:::{bucket}",
                    "CompressionType": "NONE",
                    "StorageClass": "STANDARD",
                    "OutputPrefix": "data/",
                },
                "DeadLetterQueueS3": {"BucketArn": f"arn:aws:s3:::{bucket}", "ErrorOutputPrefix": "dlq/"},
            },
            Tags={"sim2real-check": CHECK},
        ),
        acceptable_codes={"ForbiddenException", "BadRequestException"},
        timeout_s=120,
    )
    channel_arn = create_resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel(ctx, cluster_arn, channel_arn))
    before = _wait_for_channel_status(ctx, cluster_arn, channel_arn, {"ACTIVE"}, timeout_s=600)
    before_freshness = before["S3DestinationConfiguration"]["DataFreshnessInSeconds"]
    assert before_freshness == 600, (
        f"expected DataFreshnessInSeconds=600 right after CreateChannel, got {before_freshness!r}"
    )

    update_resp = kafka.update_channel(
        ChannelArn=channel_arn,
        ClusterArn=cluster_arn,
        S3DestinationUpdate={"DataFreshnessInSeconds": 900},
    )
    # UpdateChannel's modeled output is only {ChannelArn, ClusterOperationArn} -- it echoes no
    # destination fields at all, so only an independent DescribeChannel/ListChannels reveals
    # whether the mutation actually took effect. These two checks hold the thin echo itself to
    # account, rather than merely asserting the absence of fields the SDK could never surface.
    assert update_resp["ChannelArn"] == channel_arn, (
        f"UpdateChannel echoed ChannelArn={update_resp.get('ChannelArn')!r}, expected {channel_arn!r}"
    )
    cluster_operation_arn = update_resp.get("ClusterOperationArn", "")
    assert cluster_operation_arn.startswith("arn:aws:kafka:"), (
        f"UpdateChannel returned ClusterOperationArn={cluster_operation_arn!r}, "
        "expected a kafka cluster-operation ARN"
    )

    after = _wait_for_channel_config_converged(ctx, cluster_arn, channel_arn, expected_freshness=900, timeout_s=300)
    after_freshness = after["S3DestinationConfiguration"]["DataFreshnessInSeconds"]
    assert after_freshness == 900, (
        f"expected DataFreshnessInSeconds=900 from an independent DescribeChannel after UpdateChannel, "
        f"got {after_freshness!r}"
    )

    listed = kafka.list_channels(ClusterArn=cluster_arn)["Channels"]
    matching = [c for c in listed if c["ChannelArn"] == channel_arn]
    assert len(matching) == 1, f"expected exactly one ListChannels entry for {channel_arn!r}, got {len(matching)}"
    assert matching[0]["Status"] == "ACTIVE", (
        f"expected ListChannels to report Status=ACTIVE for {channel_arn!r}, got {matching[0]['Status']!r}"
    )


# ===== helpers =====

def _retry_until(fn, acceptable_codes, timeout_s=120, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in acceptable_codes or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _default_vpc_subnets_and_sg(ctx, num_azs):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an MSK cluster in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < num_azs:
        raise AssertionError(f"shared network has fewer than {num_azs} AZ-distinct network subnets")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]
    return subnet_ids[:num_azs], sg["GroupId"]


def _active_kafka_version(ctx):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    # Kafka 4.x is Express-brokers-only; standard (Provisioned) broker instance
    # types like kafka.t3.small are rejected for those versions, so restrict to
    # ACTIVE versions below the 4.x line.
    active = [
        v["Version"]
        for v in versions
        if v.get("Status") == "ACTIVE" and not v["Version"].startswith("4.")
    ]
    if not active:
        raise AssertionError("ListKafkaVersions returned no ACTIVE Kafka version below 4.x")
    return sorted(active, key=lambda s: [int(p) if p.isdigit() else p for p in s.split(".")])[-1]


def _wait_for_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info.get("State")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_states}; last observed state={last}")


def _wait_for_cluster_deleted(ctx, cluster_arn, timeout_s=1800, interval_s=20):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _create_provisioned_cluster(ctx, num_brokers=2):
    kafka = ctx.client("kafka")
    subnets, sg_id = _default_vpc_subnets_and_sg(ctx, num_brokers)
    kafka_version = _active_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "express.m7g.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
        },
        Tags={"sim2real-check": CHECK},
    )
    cluster_arn = resp["ClusterArn"]

    def _cleanup():
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        try:
            _wait_for_cluster_deleted(ctx, cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    # An Express cluster can stay in CREATING past 30 minutes, so the wait allows 2700 s.
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=2700)
    return cluster_arn, subnets, sg_id


def _wait_for_topic_status(ctx, cluster_arn, topic_name, target_states, timeout_s=180, interval_s=5):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        last = info.get("Status")
        if last in target_states:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached {target_states}; last status={last}")


def _create_topic(ctx, cluster_arn, partitions=1, replication_factor=2):
    kafka = ctx.client("kafka")
    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        PartitionCount=partitions,
        ReplicationFactor=replication_factor,
    )
    _wait_for_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"})
    return topic_name


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-msk-chan-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_channel_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-msk-chan-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    policy_name = "s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _wait_for_channel_status(ctx, cluster_arn, channel_arn, target_states, timeout_s=600, interval_s=10):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
        last = info.get("Status")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"channel entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"channel never reached {target_states}; last observed status={last}")


def _wait_for_channel_config_converged(ctx, cluster_arn, channel_arn, expected_freshness, timeout_s=300, interval_s=10):
    """Poll on the *target invariant* (DataFreshnessInSeconds), not merely on Status returning to
    ACTIVE. If a real update never transitions Status away from ACTIVE (a fast, in-place config
    change), a status-only poll would return on its first read regardless of whether the
    destination config has actually converged yet, and the field-equality assert downstream would
    read whatever happened to be there rather than the converged value."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_status = None
    last_freshness = None
    while time.monotonic() < deadline:
        info = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
        last_status = info.get("Status")
        last_freshness = info.get("S3DestinationConfiguration", {}).get("DataFreshnessInSeconds")
        if last_status == "ACTIVE" and last_freshness == expected_freshness:
            return info
        if last_status == "FAILED":
            raise AssertionError(
                f"channel entered FAILED state while converging to DataFreshnessInSeconds={expected_freshness}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"channel update to DataFreshnessInSeconds={expected_freshness} never converged within {timeout_s}s; "
        f"last observed status={last_status!r} DataFreshnessInSeconds={last_freshness!r}"
    )


def _delete_channel(ctx, cluster_arn, channel_arn):
    kafka = ctx.client("kafka")
    try:
        kafka.delete_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"channel {channel_arn} still present 600s after DeleteChannel")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
