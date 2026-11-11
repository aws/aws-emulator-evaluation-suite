"""describe-topic-partitions-nonexistent-topic-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-topic-partitions-nonexistent-topic-not-found"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTopicPartitions for a topic name that does not exist on the cluster returns
    NotFoundException, not an empty partition list -- verified against a real topic on the
    same cluster that DOES return a populated partition list (positive control).
    """
    kafka = ctx.client("kafka")
    cluster_arn = _create_provisioned_cluster(ctx)
    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=1
    )
    ctx.on_cleanup(lambda: kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name))
    _poll_until(
        lambda: [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]],
        lambda names: topic_name in names,
        timeout_s=90,
    )

    # Positive control: DescribeTopicPartitions on a real topic returns real partitions.
    real = kafka.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=topic_name)
    assert len(real["Partitions"]) == 1, (
        f"positive control: expected 1 partition for {topic_name!r}, got {real['Partitions']!r}"
    )

    # Negative: DescribeTopicPartitions on a topic that was never created is NotFoundException.
    missing_topic_name = ctx.unique_name("sim2real-behav-missing-topic-")
    code, message = _error_code(
        lambda: kafka.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=missing_topic_name)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "The requested resource doesn\u2019t exist.", f"unexpected message: {message!r}"

    # Effect absent: the nonexistent topic never shows up in ListTopics either.
    topic_names_after = [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]]
    assert missing_topic_name not in topic_names_after, (
        f"expected {missing_topic_name!r} absent from ListTopics, found in {topic_names_after!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_vpc_subnets_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span >=2 availability zones with subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _pick_kafka_version(ctx, min_version=(2, 6, 0)):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])

    def _key(v):
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (0,)

    # ListKafkaVersions includes versions CreateCluster rejects for a standard
    # (non-Express) broker instance type such as kafka.t3.small -- e.g. "3.6.0.1"
    # answers BadRequestException("Standard instance types are not supported for
    # Kafka version 3.6.0.1"). Status == ACTIVE is the set that is actually
    # provisionable; picking the raw max version number is not.
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    pool = active or [v["Version"] for v in versions]
    if not pool:
        raise AssertionError("no Kafka versions available from ListKafkaVersions")
    candidates = [v for v in pool if _key(v) >= min_version] or pool
    candidates.sort(key=_key)
    return candidates[-1]


def _create_provisioned_cluster(ctx):
    kafka = ctx.client("kafka")
    _, subnet_ids, sg_id = _default_vpc_subnets_sg(ctx)
    version = _pick_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-kafka-")
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ctx, cluster_arn))
    _wait_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _delete_cluster_when_settled(ctx, cluster_arn, timeout_s=2700.0, interval_s=30.0):
    """DeleteCluster is refused while the cluster is still CREATING, so a teardown that runs after
    a provisioning timeout waits for creation to settle before deleting."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"] == "CREATING":
        if time.monotonic() > deadline:
            raise AssertionError(f"cluster {cluster_arn} still CREATING after {timeout_s}s")
        time.sleep(interval_s)
    kafka.delete_cluster(ClusterArn=cluster_arn)


def _wait_cluster_active(ctx, cluster_arn, timeout_s=2700.0, interval_s=30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
