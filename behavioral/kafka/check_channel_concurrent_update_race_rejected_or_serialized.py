"""channel-concurrent-update-race-rejected-or-serialized."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "channel-concurrent-update-race-rejected-or-serialized"
GROUP = "concurrency"
SERVICES = ["kafka"]

_POLL_S = 2.0
# Update rounds tried to land the second UpdateChannel while the first keeps the channel UPDATING.
_ROUNDS = 3


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two UpdateChannel calls, the first is accepted while ACTIVE and the second, sent while the
    channel is UPDATING, is rejected with BadRequestException; DescribeChannel shows only the first."""
    cluster_arn, _subnets, _sg = _create_provisioned_cluster(ctx, num_brokers=3)
    topic_name = _create_topic(ctx, cluster_arn)
    topic_arn = ctx.client("kafka").describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)["TopicArn"]
    bucket = _create_bucket(ctx)
    role_arn = _create_channel_role(ctx, bucket)

    kafka = ctx.client("kafka")
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
        ),
        acceptable_codes={"ForbiddenException", "BadRequestException"},
        timeout_s=120,
    )
    channel_arn = create_resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel(ctx, cluster_arn, channel_arn))
    _wait_for_channel_status(ctx, cluster_arn, channel_arn, {"ACTIVE"}, timeout_s=600)

    def _call(freshness):
        try:
            kafka.update_channel(
                ChannelArn=channel_arn,
                ClusterArn=cluster_arn,
                S3DestinationUpdate={"DataFreshnessInSeconds": freshness},
            )
            return ("ok", freshness)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    # The calls are sequenced so the second one lands while the first keeps the channel UPDATING.
    # A round whose second call finds the channel ACTIVE again was serialized, which AWS allows,
    # and proves nothing about the rejection; the round is repeated.
    rounds = []
    winning_value = None
    for _ in range(_ROUNDS):
        current = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)[
            "S3DestinationConfiguration"]["DataFreshnessInSeconds"]
        first_value = 450 if current == 300 else 300
        first = _call(first_value)
        assert first == ("ok", first_value), (
            f"the first UpdateChannel on an ACTIVE channel must be accepted, got {first}"
        )
        status = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn).get("Status")
        second = _call(900) if status == "UPDATING" else None
        rounds.append((first, status, second))
        if second is not None and second[0] == "error":
            assert second[1] == "BadRequestException", (
                f"expected the second UpdateChannel to be rejected with BadRequestException (channel "
                f"not in a state that allows update), got {second[1]}"
            )
            assert second[2] == (
                "Channel cannot be updated in state UPDATING. Channel must be in ACTIVE state to be updated."
            ), f"second UpdateChannel rejection message: {second[2]!r}"
            winning_value = first_value
            break
        _wait_for_channel_status(ctx, cluster_arn, channel_arn, {"ACTIVE"}, timeout_s=300)
    assert winning_value is not None, (
        f"no round sent the second UpdateChannel while the first kept the channel UPDATING and saw "
        f"it rejected; (first, status before second, second) per round: {rounds}"
    )

    _wait_for_channel_status(ctx, cluster_arn, channel_arn, {"ACTIVE"}, timeout_s=300)
    described = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
    assert described["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == winning_value, (
        f"DescribeChannel shows {described['S3DestinationConfiguration']['DataFreshnessInSeconds']}, "
        f"expected exactly the winner's {winning_value} with no trace of the rejected update"
    )


def _retry_until(fn, acceptable_codes, timeout_s=120, interval_s=_POLL_S):
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


def _wait_for_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=_POLL_S):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info.get("State")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"cluster never reached {target_states}; last observed state={last}")


def _wait_for_cluster_deleted(ctx, cluster_arn, timeout_s=1800, interval_s=_POLL_S):
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
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=3000)
    return cluster_arn, subnets, sg_id


def _wait_for_topic_status(ctx, cluster_arn, topic_name, target_states, timeout_s=180, interval_s=_POLL_S):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        last = info.get("Status")
        if last in target_states:
            return info
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"topic {topic_name} reaching {target_states}: the run budget ended first; not graded")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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


def _wait_for_channel_status(ctx, cluster_arn, channel_arn, target_states, timeout_s=600, interval_s=_POLL_S):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
        last = info.get("Status")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"channel entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"channel {channel_arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"channel never reached {target_states}; last observed status={last}")


def _delete_channel(ctx, cluster_arn, channel_arn):
    kafka = ctx.client("kafka")
    try:
        kafka.delete_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return

    deadline = time.monotonic() + 600
    last = None
    while time.monotonic() < deadline:
        try:
            last = kafka.describe_channel(ChannelArn=channel_arn, ClusterArn=cluster_arn).get("Status")
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            last = err
        time.sleep(_POLL_S)
    raise RuntimeError(f"channel {channel_arn} was not deleted: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
