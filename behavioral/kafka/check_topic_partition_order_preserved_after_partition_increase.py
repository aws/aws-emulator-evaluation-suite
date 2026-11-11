"""topic-partition-order-preserved-after-partition-increase."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-partition-order-preserved-after-partition-increase"
GROUP = "ordering"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Increasing PartitionCount via UpdateTopic preserves the original partitions' leader/
    replica/ISR assignment exactly; DescribeTopicPartitions returns the untouched original
    partitions at their original indices with only the new partitions appended after them."""
    cluster_arn, _subnets, _sg = _create_provisioned_cluster(ctx, num_brokers=2)
    kafka = ctx.client("kafka")
    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3, ReplicationFactor=2)
    _wait_for_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"})

    original = _all_partitions(ctx, cluster_arn, topic_name)
    original_ids = [p["Partition"] for p in original]
    assert original_ids == [0, 1, 2], f"expected partitions [0, 1, 2] right after create, got {original_ids}"

    kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=6)
    _wait_for_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"})

    grown = _all_partitions(ctx, cluster_arn, topic_name)
    grown_ids = [p["Partition"] for p in grown]
    assert grown_ids == [0, 1, 2, 3, 4, 5], (
        f"expected the 3 original partitions plus 3 new ones appended as [0..5], got {grown_ids}"
    )

    by_id_original = {p["Partition"]: p for p in original}
    by_id_grown = {p["Partition"]: p for p in grown}
    for partition_id in (0, 1, 2):
        before = by_id_original[partition_id]
        after = by_id_grown[partition_id]
        assert after["Leader"] == before["Leader"], (
            f"partition {partition_id} leader changed after partition increase: "
            f"{before['Leader']} -> {after['Leader']}"
        )
        assert sorted(after["Replicas"]) == sorted(before["Replicas"]), (
            f"partition {partition_id} replica set changed after partition increase"
        )


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
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
        },
        Tags={"sim2real:managed": "true"},
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


def _all_partitions(ctx, cluster_arn, topic_name):
    kafka = ctx.client("kafka")
    partitions = []
    token = None
    while True:
        kwargs = {"ClusterArn": cluster_arn, "TopicName": topic_name}
        if token:
            kwargs["NextToken"] = token
        resp = kafka.describe_topic_partitions(**kwargs)
        partitions.extend(resp.get("Partitions", []))
        token = resp.get("NextToken")
        if not token:
            break
    return sorted(partitions, key=lambda p: p["Partition"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
