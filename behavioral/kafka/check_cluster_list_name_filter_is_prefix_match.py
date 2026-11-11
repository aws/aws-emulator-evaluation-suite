"""cluster-list-name-filter-is-prefix-match."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-list-name-filter-is-prefix-match"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"
_NET_TEARDOWN_S = 1800


def _tag_spec(resource_type, name):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real:managed", "Value": "true"}],
    }


def _create_cluster_network(ctx, num_subnets=2):
    """Create the check's own VPC, one subnet per distinct AZ and a security group, all
    with teardown registered. Returns (vpc_id, subnet_ids, sg_id)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-kafka-net-")
    vpc_id = ec2.create_vpc(CidrBlock="10.93.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    zones = ec2.describe_availability_zones(
        Filters=[
            {"Name": "zone-type", "Values": ["availability-zone"]},
            {"Name": "state", "Values": ["available"]},
        ]
    )["AvailabilityZones"]
    az_names = sorted(z["ZoneName"] for z in zones)[:num_subnets]
    if len(az_names) < num_subnets:
        raise AssertionError(f"region {ctx.region} offers fewer than {num_subnets} availability zones")

    subnet_ids = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real MSK cluster check network",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return vpc_id, subnet_ids, sg_id


_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(ec2, op, **ident):
    """Teardown for a network resource: wait (bounded) for MSK's broker ENIs to go, then
    delete, retrying DependencyViolation until the same bound."""
    deadline = time.monotonic() + _NET_TEARDOWN_S
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while flt and ec2.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]:
        if time.monotonic() >= deadline:
            break
        time.sleep(15)
    while True:
        try:
            getattr(ec2, op)(**ident)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(15)


def _provisioned_body(subnet_ids, sg_id, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                      instance_type=_PROVISIONED_INSTANCE_TYPE, volume_size=10):
    return {
        "BrokerNodeGroupInfo": {
            "InstanceType": instance_type,
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": volume_size}},
        },
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": num_brokers,
    }


def _wait_cluster_settled(msk, arn, timeout_s=2700, interval_s=20):
    """Bounded poll until the cluster leaves CREATING. Returns the state it settles in, or
    None once it is gone; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return None
            raise
        if state != "CREATING":
            return state
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still CREATING after {timeout_s}s")
        time.sleep(interval_s)


def _delete_cluster_and_wait(msk, arn, timeout_s=2700, interval_s=20):
    """Teardown: wait for the cluster to leave CREATING (MSK refuses DeleteCluster before),
    delete it, and wait until it is gone so the network teardown can follow."""
    if _wait_cluster_settled(msk, arn, timeout_s=timeout_s) is None:
        return
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            msk.describe_cluster_v2(ClusterArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still present {timeout_s}s after DeleteCluster")
        time.sleep(interval_s)


def _wait_cluster_terminal(msk, arn, timeout_s=2700, interval_s=20):
    """Bounded poll CREATING -> ACTIVE; returns the ACTIVE ClusterInfo, raises on FAILED or timeout."""
    state = _wait_cluster_settled(msk, arn, timeout_s=timeout_s, interval_s=interval_s)
    info = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
    assert state == "ACTIVE" and info["State"] == "ACTIVE", f"cluster settled in {state}, not ACTIVE: {info}"
    return info


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClustersV2/ListClusters show the new ACTIVE cluster, and ClusterNameFilter is a prefix
    filter: the full name and a strict prefix match, a non-prefix substring does not."""
    msk = ctx.client("kafka")
    _vpc, subnets, sg = _create_cluster_network(ctx, num_subnets=2)
    name = ctx.unique_name("sim2real-behav-cluster-")
    arn = msk.create_cluster_v2(
        ClusterName=name,
        Provisioned=_provisioned_body(subnets, sg, num_brokers=2),
        Tags={"sim2real:managed": "true"},
    )["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(msk, arn))
    _wait_cluster_terminal(msk, arn)

    exact = msk.list_clusters_v2(ClusterNameFilter=name)["ClusterInfoList"]
    assert [c["ClusterArn"] for c in exact] == [arn], exact
    assert exact[0]["State"] == "ACTIVE", exact
    assert exact[0]["ClusterType"] == "PROVISIONED", exact

    prefix = name[: len(name) - 4]
    by_prefix = msk.list_clusters_v2(ClusterNameFilter=prefix)["ClusterInfoList"]
    assert arn in [c["ClusterArn"] for c in by_prefix], (prefix, by_prefix)

    # A non-prefix substring must not match (prefix semantics, not "contains").
    suffix = name[-6:]
    by_suffix = msk.list_clusters_v2(ClusterNameFilter=suffix)["ClusterInfoList"]
    assert arn not in [c["ClusterArn"] for c in by_suffix], (suffix, by_suffix)

    # The v1 lister must agree.
    v1 = msk.list_clusters(ClusterNameFilter=name)["ClusterInfoList"]
    assert [c["ClusterArn"] for c in v1] == [arn], v1


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
