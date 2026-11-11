"""update-topic-controller-moved-exception-during-leader-election."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-topic-controller-moved-exception-during-leader-election"
GROUP = "error-semantics"
SERVICES = ["kafka"]

_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTopic for a never-created topic fails with the generic NotFoundException, not
    UnknownTopicOrPartitionException; the rejected call leaves nothing behind, and the same
    cluster still accepts UpdateTopic on a topic that exists.
    """


    cluster_arn, _subnets, _sg = _create_provisioned_cluster(ctx, num_brokers=2)
    kafka = ctx.client("kafka")
    real_topic = _create_topic(ctx, cluster_arn, partitions=2)
    missing_topic = ctx.unique_name("sim2real-behav-missing-topic-")

    code = _error_code(lambda: kafka.update_topic(ClusterArn=cluster_arn, TopicName=missing_topic, PartitionCount=4))
    assert code == _NOT_FOUND, (
        f"expected UpdateTopic on a nonexistent topic to fail with {_NOT_FOUND!r}, got {code!r}"
    )

    # The rejected call must leave no trace: the topic still does not exist.
    still_missing = _error_code(lambda: kafka.describe_topic(ClusterArn=cluster_arn, TopicName=missing_topic))
    assert still_missing == _NOT_FOUND, (
        f"expected the rejected UpdateTopic to leave the topic still absent ({_NOT_FOUND!r} "
        f"on DescribeTopic), got {still_missing!r}"
    )

    # Positive control: the exact same cluster still accepts a real UpdateTopic on the
    # topic that does exist, and the partition increase actually takes effect.
    kafka.update_topic(ClusterArn=cluster_arn, TopicName=real_topic, PartitionCount=4)
    updated = _wait_for_topic_status(ctx, cluster_arn, real_topic, {"ACTIVE"})
    assert updated["PartitionCount"] == 4, (
        f"expected the positive-control UpdateTopic to raise PartitionCount to 4, "
        f"got {updated['PartitionCount']!r}"
    )


def _error_code(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _default_vpc_subnets_and_sg(ctx, num_azs):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < num_azs:
        raise AssertionError(f"VPC {vpc_id} has fewer than {num_azs} AZ-distinct subnets")
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
        Tags={"sim2real:managed": "true"},
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
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
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=1800)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
