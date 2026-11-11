"""list-nodes-broker-id-stable-ordering."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-nodes-broker-id-stable-ordering"
GROUP = "ordering"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNodes returns exactly the cluster's broker IDs on each repeated call to an unchanged
    cluster; AWS documents no order (e.g. [2, 3, 1]), so listings compare order-insensitively."""
    kafka = ctx.client("kafka")
    _, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    cluster_arn = _create_cluster(ctx, subnet_ids, sg_id, num_brokers=3)

    orderings = []
    for _ in range(3):
        nodes = _list_nodes(kafka, cluster_arn)
        broker_ids = [int(n["BrokerNodeInfo"]["BrokerId"]) for n in nodes]
        orderings.append(broker_ids)
        time.sleep(1.0)

    assert len(orderings[0]) == 3, f"expected 3 broker nodes, got {orderings[0]}"
    assert sorted(orderings[0]) == [1, 2, 3], f"expected broker IDs {{1,2,3}}, got {orderings[0]}"
    for ordering in orderings[1:]:
        assert ordering == orderings[0] or sorted(ordering) == sorted(orderings[0]), (
            f"ListNodes broker IDs changed across repeated calls against an unchanged cluster: "
            f"{orderings[0]} vs {ordering}"
        )


def _list_nodes(kafka, cluster_arn):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = kafka.list_nodes(ClusterArn=cluster_arn, **kwargs)
        out.extend(resp.get("NodeInfoList", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _default_vpc_subnets(ctx, min_count: int = 3):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:3]
    if len(subnet_ids) < 2:
        raise AssertionError("fewer than 2 AZ subnets available in the VPC to place MSK brokers")
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    return vpc_id, subnet_ids, sgs[0]["GroupId"]


def _pick_kafka_version(kafka) -> str:
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions returned by ListKafkaVersions")
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return active[0] if active else versions[-1]["Version"]


def _create_cluster(ctx, subnet_ids, sg_id, num_brokers: int) -> str:
    kafka = ctx.client("kafka")
    # NumberOfBrokerNodes must be a multiple of the number of client subnets provided.
    subnets = (subnet_ids * ((num_brokers // len(subnet_ids)) + 1))[:num_brokers]
    name = ctx.unique_name("sim2real-nodes-")
    version = _pick_kafka_version(kafka)
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=num_brokers,
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnets,
            "SecurityGroups": [sg_id],
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=1800)
    return arn


def _delete_cluster(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        _wait_until_deletable(kafka, arn)
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    _wait_cluster_deleted(ctx, arn, timeout_s=1800)


def _wait_cluster_state(ctx, arn, target_states, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_cluster_deleted(ctx, arn, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("cluster did not delete within timeout")



def _wait_until_deletable(kafka, arn, timeout_s=1500.0, interval_s=20.0):
    """MSK refuses DeleteCluster while the cluster is still CREATING or UPDATING; wait it out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state not in ("CREATING", "UPDATING", "REBOOTING_BROKER", "HEALING"):
            return
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
