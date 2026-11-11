"""e2e-topic-lifecycle-scale-and-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-topic-lifecycle-scale-and-teardown"
GROUP = "e2e"
SERVICES = ["kafka"]

#: MSK's control-plane refusal for a topic the cluster does not hold (measured on real AWS; the
#: apostrophe is U+2019, not ASCII).
_TOPIC_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTopic's partition increase shows in DescribeTopicPartitions; after deletion DescribeTopic
    refuses the topic, and the cluster goes DELETING until DescribeCluster refuses it too."""
    kafka = ctx.client("kafka")
    infra = _create_vpc_infra(ctx)
    cluster_arn = _create_provisioned_cluster(ctx, kafka, infra, num_brokers=2)

    topic_name = ctx.unique_name("sim2real-topic-")
    kafka.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=2
    )
    _wait_topic_state(ctx, kafka, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180.0)

    kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3)
    _wait_topic_state(ctx, kafka, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180.0)

    partitions = _wait_partition_count(ctx, kafka, cluster_arn, topic_name, 3, timeout_s=180.0)
    assert len(partitions) == 3, f"expected 3 partitions after scale-up, got {len(partitions)}"

    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    gone = _wait_topic_gone(ctx, kafka, cluster_arn, topic_name, timeout_s=180.0)
    assert gone == _TOPIC_NOT_FOUND, f"expected {_TOPIC_NOT_FOUND!r} describing the deleted topic, got {gone!r}"

    deleted = kafka.delete_cluster(ClusterArn=cluster_arn)
    assert deleted["State"] == "DELETING", (
        f"expected DeleteCluster to answer DELETING, got {deleted.get('State')!r}"
    )
    # Then poll until DescribeCluster refuses the cluster, the terminal state.
    gone_code = _wait_cluster_gone(ctx, kafka, cluster_arn, timeout_s=1800.0)
    assert gone_code == "NotFoundException", (
        f"expected NotFoundException describing the deleted cluster, got {gone_code!r}"
    )


# ===== helpers =====

def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-kafka-e2e-")
    vpc_id = ec2.create_vpc(CidrBlock="10.80.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]
    subnet_ids = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.80.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka e2e sg",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_provisioned_cluster(ctx, kafka, infra: dict, num_brokers: int = 2) -> str:
    name = ctx.unique_name("sim2real-kafka-e2e")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [v for v in versions if v.get("Status", "ACTIVE") == "ACTIVE"]
    kafka_version = (active or versions)[0]["Version"]

    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=num_brokers,
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": infra["subnet_ids"],
            "SecurityGroups": [infra["sg_id"]],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]

    # run() waits for the cluster to go on the pass path; this covers a failure before that and
    # runs before the network teardown registered above it.
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn, gone_s=1800))
    # The transition to ACTIVE takes 1420-1572s on real AWS, so 1500s is too short; 2700s keeps a
    # slow-but-correct cluster from being graded as a stuck one.
    _wait_cluster_state(ctx, kafka, cluster_arn, {"ACTIVE"}, timeout_s=2700.0)
    return cluster_arn


#: Cluster states in which MSK refuses DeleteCluster; teardown waits them out first.
_CLUSTER_BUSY_STATES = ("CREATING", "UPDATING", "REBOOTING_BROKER")


def _delete_cluster_and_wait(kafka, arn, settle_s=2700, gone_s=2700, interval_s=20):
    """Teardown: wait for the cluster to settle (MSK refuses DeleteCluster while it is CREATING or
    applying an operation), delete it, and poll until it is gone so the network teardown can
    follow. Raises on either timeout; NotFound at any point means the cluster is already gone."""
    deadline = time.monotonic() + settle_s
    while True:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        if state not in _CLUSTER_BUSY_STATES:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {settle_s}s; DeleteCluster not issued")
        time.sleep(interval_s)
    if state != "DELETING":
        try:
            kafka.delete_cluster(ClusterArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    deadline = time.monotonic() + gone_s
    while True:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} {gone_s}s after DeleteCluster")
        time.sleep(interval_s)


def _wait_cluster_state(ctx, kafka, cluster_arn: str, target_states: set, timeout_s: float = 1800.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        last = state
        if state in target_states:
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster entered FAILED: {info.get('StateInfo')}")
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_states} (last={last})")


def _wait_cluster_gone(ctx, kafka, cluster_arn: str, timeout_s: float = 1800.0) -> str:
    """Poll DescribeCluster until it is refused; return the refusal's error code."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        except ClientError as err:
            return err.response["Error"].get("Code")
        if last == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED while deleting")
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s (last={last})")
        time.sleep(2)


def _wait_topic_state(ctx, kafka, cluster_arn: str, topic_name: str, target_states: set, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        topic = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        state = topic["Status"]
        last = state
        if state in target_states:
            return topic
        time.sleep(5.0)
    raise AssertionError(f"topic never reached {target_states} (last={last})")


def _wait_topic_gone(ctx, kafka, cluster_arn: str, topic_name: str, timeout_s: float = 180.0) -> tuple:
    """Poll DescribeTopic until it is refused; return the refusal's (Code, Message)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)["Status"]
        except ClientError as err:
            return err.response["Error"].get("Code"), err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"topic {topic_name} was not deleted within {timeout_s}s (last={last})")
        time.sleep(5.0)


def _wait_partition_count(ctx, kafka, cluster_arn: str, topic_name: str, count: int, timeout_s: float = 180.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        partitions = kafka.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=topic_name)["Partitions"]
        last = len(partitions)
        if last == count:
            return partitions
        time.sleep(5.0)
    raise AssertionError(f"partition count never reached {count} (last={last})")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is
# shared by all of one check's network deletes and starts once the cluster is gone.
_NET_TEARDOWN_S = 1800.0
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
        _time.sleep(10)
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
        _time.sleep(10)


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
