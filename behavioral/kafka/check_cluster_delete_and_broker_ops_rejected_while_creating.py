"""cluster-delete-and-broker-ops-rejected-while-creating."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-delete-and-broker-ops-rejected-while-creating"
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
        time.sleep(2)
    while True:
        try:
            getattr(ec2, op)(**ident)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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


def _wait_cluster_settled(msk, arn, timeout_s=2700, interval_s=20, ctx=None):
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
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"cluster {arn} leaving CREATING: the run budget ended first; not graded")
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


def _wait_cluster_terminal(msk, arn, timeout_s=2700, interval_s=20, ctx=None):
    """Bounded poll CREATING -> ACTIVE; returns the ACTIVE ClusterInfo, raises on FAILED or timeout."""
    state = _wait_cluster_settled(msk, arn, timeout_s=timeout_s, interval_s=interval_s, ctx=ctx)
    info = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
    assert state == "ACTIVE" and info["State"] == "ACTIVE", f"cluster settled in {state}, not ACTIVE: {info}"
    return info


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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
    """A CREATING cluster refuses DeleteCluster, ListNodes, GetBootstrapBrokers and RebootBroker
    with exact BadRequestException texts; none takes effect, and once ACTIVE nodes and brokers
    are served.
    """
    msk = ctx.client("kafka")
    # A provisioned cluster takes tens of minutes to leave CREATING, so the probes below land inside
    # the provisioning window.
    arn, created = _create_own_cluster(ctx, msk, name_prefix="guard-")
    assert created["State"] == "CREATING", f"expected CreateClusterV2 to answer CREATING, got {created['State']}"

    # The refusals go straight after the create, so the CreateClusterV2 answer and the describe
    # below bracket them inside the CREATING window; DeleteCluster goes last.
    refusals = {
        "ListNodes": _refusal(lambda: msk.list_nodes(ClusterArn=arn)),
        "GetBootstrapBrokers": _refusal(lambda: msk.get_bootstrap_brokers(ClusterArn=arn)),
        "RebootBroker": _refusal(lambda: msk.reboot_broker(ClusterArn=arn, BrokerIds=["1"])),
        "DeleteCluster": _refusal(lambda: msk.delete_cluster(ClusterArn=arn)),
    }
    expected = {
        "DeleteCluster": ("BadRequestException", "You can't delete cluster in CREATING state."),
        "ListNodes": (
            "BadRequestException",
            "You can't list the nodes for a cluster that is in the CREATING state.",
        ),
        "GetBootstrapBrokers": (
            "BadRequestException",
            "You can't get bootstrap broker nodes for a cluster in CREATING state.",
        ),
        "RebootBroker": ("BadRequestException", _ACTIVE_ONLY_MSG),
    }
    assert refusals == expected, f"expected refusals {expected}, got {refusals}"
    after = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
    assert after == "CREATING", f"cluster state changed after rejected operations: {after}"

    # The refused delete did not take effect: the cluster settles in ACTIVE, and the
    # broker reads refused above are served once it has.
    _wait_cluster_terminal(msk, arn, timeout_s=_budget_s(ctx, 2700.0), interval_s=2, ctx=ctx)
    nodes = msk.list_nodes(ClusterArn=arn)["NodeInfoList"]
    assert len(nodes) == 2, f"expected 2 broker nodes once ACTIVE, got {len(nodes)}: {nodes}"
    brokers = msk.get_bootstrap_brokers(ClusterArn=arn)
    endpoints = {k: v for k, v in brokers.items() if k.startswith("BootstrapBrokerString") and v}
    assert endpoints, f"expected bootstrap broker endpoints once ACTIVE, got {brokers}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
