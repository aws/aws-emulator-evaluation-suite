"""describe-topic-partitions-invalid-topic-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-topic-partitions-invalid-topic-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTopicPartitions for a topic name that does not exist on a real cluster
    is rejected with NotFoundException rather than returning an empty partition list."""
    cluster_arn = _create_active_msk_cluster(ctx)
    kafka = ctx.client("kafka")

    # Positive control: create a real topic and confirm DescribeTopicPartitions
    # reports its actual partitions.
    topic_name = ctx.unique_name("sim2real-topic-")
    kafka.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3, ReplicationFactor=2
    )
    ctx.on_cleanup(lambda: _delete_topic_best_effort(kafka, cluster_arn, topic_name))

    partitions = _wait_for_topic_partitions(kafka, cluster_arn, topic_name, expected=3, timeout_s=180.0)
    assert len(partitions) == 3

    # Negative: a topic name that was never created on this cluster.
    code, message = _error_code(
        lambda: kafka.describe_topic_partitions(
            ClusterArn=cluster_arn, TopicName=ctx.unique_name("never-created-topic-")
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "The requested resource doesn\u2019t exist.", f"unexpected message: {message!r}"


def _default_vpc_subnets(ctx, count=2):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError(
            "shared network does not have enough distinct-AZ subnets to provision an MSK cluster"
        )
    return vpc_id, subnet_ids[:count]


def _create_active_msk_cluster(ctx, *, sasl_scram: bool = False, timeout_s: float = 1800.0) -> str:
    kafka = ctx.client("kafka")
    _, subnets = _default_vpc_subnets(ctx, 2)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    kafka_version = next((v["Version"] for v in versions if v.get("Status") == "ACTIVE"), None)
    if not kafka_version and versions:
        kafka_version = versions[0]["Version"]
    if not kafka_version:
        kafka_version = "3.9.x"

    provisioned = {
        "BrokerNodeGroupInfo": {"InstanceType": "kafka.m5.large", "ClientSubnets": subnets},
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": len(subnets),
    }
    if sasl_scram:
        provisioned["ClientAuthentication"] = {"Sasl": {"Scram": {"Enabled": True}}}

    name = ctx.unique_name("sim2real-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name, Provisioned=provisioned, Tags={"sim2real:managed": "true"}
    )
    arn = resp["ClusterArn"]

    def _cleanup():
        try:
            info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
            if info["State"] != "DELETING":
                kafka.delete_cluster(ClusterArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    state = "CREATING"
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        state = info["State"]
        if state in ("ACTIVE", "FAILED"):
            break
        time.sleep(2)
    if state != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE within {timeout_s}s (state={state})")
    return arn


def _wait_for_topic_partitions(kafka, cluster_arn, topic_name, *, expected, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    partitions: list = []
    while time.monotonic() < deadline:
        try:
            partitions = kafka.describe_topic_partitions(
                ClusterArn=cluster_arn, TopicName=topic_name
            ).get("Partitions", [])
        except Exception:
            partitions = []
        if len(partitions) >= expected:
            return partitions
        time.sleep(5)
    raise AssertionError(f"topic {topic_name} never reported {expected} partitions (got {partitions})")


def _delete_topic_best_effort(kafka, cluster_arn, topic_name):
    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
