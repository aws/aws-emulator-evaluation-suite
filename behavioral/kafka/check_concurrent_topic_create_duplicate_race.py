"""concurrent-topic-create-duplicate-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-topic-create-duplicate-race"
GROUP = "concurrency"
SERVICES = ["kafka"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real", "Value": "kafka-topic-race"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two racing identical CreateTopic calls are both accepted and name one TopicArn, listed once as
    ACTIVE; a CreateTopic after it is ACTIVE fails with TopicExistsException, and an unrelated topic
    still creates normally."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_minimal_cluster(ctx, "sim2real-topicrace")

    topic_name = ctx.unique_name("sim2real-race-topic-")

    def _create():
        return _call_capture(
            lambda: kafka.create_topic(
                ClusterArn=cluster_arn,
                TopicName=topic_name,
                PartitionCount=1,
                ReplicationFactor=2,
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        results = [f.result() for f in futures]

    oks = [r for r in results if r[0] == "ok"]
    assert len(oks) == 2, f"expected both racing CreateTopic calls to be accepted, got {results}"
    arns = {r[1]["TopicArn"] for r in oks}
    assert len(arns) == 1, f"expected both racing CreateTopic calls to name one topic, got {sorted(arns)}"

    _wait_topic_active(ctx, cluster_arn, topic_name, timeout_s=300.0)
    topics = kafka.list_topics(ClusterArn=cluster_arn).get("Topics", [])
    matching = [t for t in topics if t.get("TopicName") == topic_name]
    assert len(matching) == 1, f"expected exactly one topic named {topic_name}, found {matching}"
    assert matching[0]["TopicArn"] in arns, f"listed topic {matching[0]!r} is not the one both calls named"

    # Once the topic exists, the name is taken.
    late = _create()
    assert late == ("error", "TopicExistsException"), (
        f"expected a CreateTopic after the topic is ACTIVE to fail with TopicExistsException, got {late}"
    )

    # Positive control: creation still works for a fresh, non-colliding name.
    control_name = ctx.unique_name("sim2real-race-control-")
    kafka.create_topic(
        ClusterArn=cluster_arn,
        TopicName=control_name,
        PartitionCount=1,
        ReplicationFactor=2,
    )
    _wait_topic_active(ctx, cluster_arn, control_name, timeout_s=300.0)


# ===== helpers =====


def _call_capture(fn):
    from botocore.exceptions import ClientError

    try:
        return ("ok", fn())
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


def _delete_with_retry(fn, transient_code, timeout_s=180.0, interval_s=2.0):
    """Retry a delete through a transient DependencyViolation window: an MSK cluster's ENIs in this
    network detach after DeleteCluster returns, so a single attempt can be refused."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == transient_code and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_own_network(ctx, count: int):
    """A VPC and `count` subnets in distinct AZs, created fresh — never adopted from a default VPC.

    An account may not have a default VPC at all, so this check brings its own. Registered for
    cleanup immediately: a failure between here and the cluster create must not strand this network.
    """
    import random

    ec2 = ctx.client("ec2")
    cidr_base = random.randrange(20, 250)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{cidr_base}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "DependencyViolation")
    )
    # MSK's CreateClusterV2 refuses a VPC with DNS hostnames disabled (the default for a
    # non-default VPC): "VPC ... doesn't have DNS hostnames enabled" (measured on real AWS).
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    ).get("AvailabilityZones", [])
    if len(azs) < count:
        raise AssertionError(f"region has fewer than {count} available availability zones")

    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.{cidr_base}.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_with_retry(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "DependencyViolation"
            )
        )
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_security_group(ctx, vpc_id: str, name: str) -> str:
    """A group with no ingress rule: the check never opens a connection to the brokers."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _MANAGED_TAGS}],
    )["GroupId"]

    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "DependencyViolation"
        )
    )
    return sg_id


def _wait_cluster_active(ctx, cluster_arn: str, timeout_s: float = 1800.0, interval_s: float = 30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info.get("State")
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state: {info}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s")


def _wait_topic_active(ctx, cluster_arn: str, topic_name: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except Exception:
            last = None
        if last and last.get("Status") == "ACTIVE":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} did not reach ACTIVE within {timeout_s}s (last: {last})")


_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"
# Standard brokers accept 3.9.x; CreateClusterV2 refuses them on 3.6.0 ("Standard instance types
# are not supported for Kafka version 3.6.0", observed on real AWS).
_KAFKA_VERSION = "3.9.x"
_NUM_BROKERS = 2


def _create_minimal_cluster(ctx, name_prefix: str) -> str:
    """A PROVISIONED (Standard-broker) cluster: the CreateTopic/DescribeTopic/ListTopics API exists
    only for Provisioned clusters (Serverless answers ServerlessUnsupportedException), and one takes
    15-30 minutes to reach ACTIVE on AWS.
    """
    kafka = ctx.client("kafka")
    vpc_id, subnets = _create_own_network(ctx, _NUM_BROKERS)
    sg_id = _create_security_group(ctx, vpc_id, ctx.unique_name(f"{name_prefix}-sg-"))

    cluster_name = ctx.unique_name(f"{name_prefix}-")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=cluster_name,
        Provisioned={
            "KafkaVersion": _KAFKA_VERSION,
            "NumberOfBrokerNodes": _NUM_BROKERS,
            "ClientAuthentication": {"Unauthenticated": {"Enabled": True}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS_PLAINTEXT", "InCluster": True}},
            "BrokerNodeGroupInfo": {
                "InstanceType": _PROVISIONED_INSTANCE_TYPE,
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
            },
        },
        Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS},
    )["ClusterArn"]

    # The delete is registered immediately so it fires on any run that reaches ACTIVE (or FAILED);
    # the managed tags identify the cluster if a run stops while it is still CREATING.
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn))
    _wait_cluster_active(ctx, cluster_arn, timeout_s=2700.0)
    return cluster_arn


def _delete_cluster_and_wait(kafka, cluster_arn, timeout_s=900.0):
    """Waits until the cluster is gone, so the network teardown after it is not held by its ENIs."""
    try:
        kafka.delete_cluster(ClusterArn=cluster_arn)
    except kafka.exceptions.NotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except kafka.exceptions.NotFoundException:
            return
        time.sleep(20.0)
    raise AssertionError(f"cluster {cluster_arn} still present {timeout_s}s after DeleteCluster")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes and fits the suite's cleanup budget together with the cluster delete.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
