"""bootstrap-brokers-availability-gate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bootstrap-brokers-availability-gate"
GROUP = 'cluster-state-guards'
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


def _refusal(fn):
    """Call fn(), which must be refused; return (Error.Code, Error.Message). A call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_own_cluster(ctx, msk, name_prefix="cluster-"):
    """Create the check's own network and PROVISIONED cluster with teardown registered.
    Returns (arn, CreateClusterV2 response)."""
    _vpc, subnets, sg = _create_cluster_network(ctx, num_subnets=2)
    resp = msk.create_cluster_v2(
        ClusterName=ctx.unique_name("sim2real-behav-" + name_prefix),
        Provisioned=_provisioned_body(subnets, sg, num_brokers=2),
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(msk, arn))
    return arn, resp


_ACTIVE_ONLY_MSG = "This operation is only valid for resources that are in one of the following states :[ACTIVE]"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBootstrapBrokers on a CREATING cluster fails with BadRequestException and its exact message, an
    unknown cluster fails with NotFoundException, and the same cluster returns endpoints once ACTIVE."""
    msk = ctx.client("kafka")
    arn, created = _create_own_cluster(ctx, msk, name_prefix="bootstrap-")
    assert created["State"] == "CREATING", f"expected CreateClusterV2 to answer CREATING, got {created['State']}"

    early = _refusal(lambda: msk.get_bootstrap_brokers(ClusterArn=arn))
    assert early == (
        "BadRequestException",
        "You can't get bootstrap broker nodes for a cluster in CREATING state.",
    ), f"expected the provisioning-window refusal, got {early}"

    ghost_arn = (
        f"arn:aws:kafka:{ctx.region}:{ctx.account}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )
    ghost = _refusal(lambda: msk.get_bootstrap_brokers(ClusterArn=ghost_arn))
    assert ghost == ("NotFoundException", "The requested resource doesn’t exist."), (
        f"ghost cluster: expected NotFoundException, got {ghost}"
    )

    # Positive control: the same call on the same cluster is served once it is ACTIVE.
    _wait_cluster_terminal(msk, arn)
    brokers = msk.get_bootstrap_brokers(ClusterArn=arn)
    endpoints = {k: v for k, v in brokers.items() if k.startswith("BootstrapBrokerString") and v}
    assert endpoints, f"expected bootstrap broker endpoints once ACTIVE, got {brokers}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
