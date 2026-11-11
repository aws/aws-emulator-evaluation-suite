"""create-topic-duplicate-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-topic-duplicate-rejected"
GROUP = "data-plane"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTopic for a name that already exists on the cluster is rejected
    with TopicExistsException, and the pre-existing topic's shape (partition
    count, replication factor, ARN) is left completely unaffected."""
    kafka = ctx.client("kafka")
    _, subnets, sg = _default_vpc_and_subnets(ctx)
    version = _pick_kafka_version(ctx, kafka)
    name = ctx.unique_name("sim2real-behav-kafka-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Tags={"sim2real:managed": "true"},
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.t3.small",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 10}},
            },
            "KafkaVersion": version,
            "NumberOfBrokerNodes": len(subnets),
        },
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, kafka, cluster_arn))
    _wait_for_cluster_active(ctx, kafka, cluster_arn)

    topic_name = ctx.unique_name("sim2real-behav-topic-")
    # Positive control: the first creation succeeds.
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3, ReplicationFactor=2)
    original = _wait_for_topic_active(ctx, kafka, cluster_arn, topic_name)
    original_arn = original["TopicArn"]

    # Negative: a second creation of the exact same name is rejected.
    code, status, message = _error_code(
        lambda: kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=2)
    )
    assert code == "TopicExistsException", f"expected TopicExistsException for a duplicate CreateTopic, got {code!r}"
    # The service model binds TopicExistsException to HTTP 409.
    assert status == 409, f"expected HTTP 409 for the duplicate CreateTopic, got {status}"
    expected_message = "Topic already exists."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # The effect of the rejected call must be absent: the original topic's shape is untouched.
    unaffected = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    assert unaffected["TopicArn"] == original_arn, (
        f"rejected duplicate CreateTopic mutated the topic ARN: expected {original_arn!r}, got {unaffected['TopicArn']!r}"
    )
    assert unaffected["PartitionCount"] == 3, (
        f"rejected duplicate CreateTopic changed PartitionCount: expected 3, got {unaffected['PartitionCount']!r}"
    )
    assert unaffected["ReplicationFactor"] == 2, (
        f"rejected duplicate CreateTopic changed ReplicationFactor: expected 2, got {unaffected['ReplicationFactor']!r}"
    )

    topics = {t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]}
    assert topic_name in topics, f"topic {topic_name!r} missing from ListTopics after a rejected duplicate create"
    dup_count = sum(1 for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"] if t["TopicName"] == topic_name)
    assert dup_count == 1, f"expected exactly 1 topic named {topic_name!r} after the rejected duplicate, found {dup_count}"

    # Restore: freeing the name (by deleting the original topic) must let the identical
    # create succeed again — proving the rejection was keyed on the name still being taken,
    # not on some permanent inability to create this topic.
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    _wait_for_topic_gone(ctx, kafka, cluster_arn, topic_name)
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3, ReplicationFactor=2)
    recreated = _wait_for_topic_active(ctx, kafka, cluster_arn, topic_name)
    assert recreated["TopicArn"], "recreating the topic after freeing its name did not return a TopicArn"


# ===== helpers =====


def _error_code(fn):
    """Call fn(); return (Error.Code, HTTP status, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            e.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _default_vpc_and_subnets(ctx, count=2):
    """The account's shared network (account baseline), its network subnets in `count` distinct AZs,
    and that VPC's default security group, to place the MSK broker ENIs in."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "this account has no shared network VPC (account baseline) to place MSK brokers in"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for sn in sorted(subnets, key=lambda x: x["AvailabilityZone"]):
        if sn.get("State") == "available":
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= count, f"the shared network has network subnets in {len(by_az)} AZs, need {count}"
    subnet_ids = [by_az[az] for az in sorted(by_az)][:count]
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    assert groups, f"the shared network {vpc_id} has no default security group"
    return vpc_id, subnet_ids, groups[0]["GroupId"]


def _pick_kafka_version(ctx, kafka):
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return (active or [v["Version"] for v in versions])[0]


def _delete_cluster(ctx, kafka, arn):
    from botocore.exceptions import ClientError

    # DeleteCluster is refused while the cluster is still CREATING, so a teardown that runs
    # after a provisioning timeout waits for creation to settle, within the suite's cleanup budget.
    deadline = time.monotonic() + 1740
    try:
        while kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"] == "CREATING":
            if time.monotonic() > deadline:
                raise AssertionError(f"cluster {arn} still CREATING after 1740s")
            time.sleep(2)
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _wait_for_cluster_active(ctx, kafka, arn, timeout_s=2700, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not reach ACTIVE within {timeout_s}s (last={last_state})")


def _wait_for_topic_active(ctx, kafka, cluster_arn, topic_name, timeout_s=180, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            last = resp.get("Status")
            if last == "ACTIVE":
                return resp
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} did not become ACTIVE (last status={last})")


def _wait_for_topic_gone(ctx, kafka, cluster_arn, topic_name, timeout_s=180, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = "unknown"
    while time.monotonic() < deadline:
        try:
            last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Status")
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NotFoundException", "UnknownTopicOrPartitionException"):
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} was not deleted within {timeout_s}s (last status={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
