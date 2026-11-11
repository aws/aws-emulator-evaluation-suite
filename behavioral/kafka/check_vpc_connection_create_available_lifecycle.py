"""vpc-connection-create-available-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-connection-create-available-lifecycle"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises, or "present" when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return "present"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _discover_network(ctx, minimum_subnets=2):
    """The run's shared network (ctx.network()): its VPC, up to three of its subnets in distinct
    availability zones, and the VPC's default security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:3], net.security_group_id


def _create_cluster_network(ctx, num_subnets=2):
    """Shared per-check discovered network (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_net"):
        ctx._kafka_net = _discover_network(ctx, minimum_subnets=2)
    vpc_id, subnet_ids, sg_id = ctx._kafka_net
    if num_subnets > len(subnet_ids):
        raise AssertionError(f"discovered network only has {len(subnet_ids)} subnets, need {num_subnets}")
    return vpc_id, subnet_ids[:num_subnets], sg_id


def _provisioned_body(subnet_ids, sg_id, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                      instance_type=_PROVISIONED_INSTANCE_TYPE, volume_size=10):
    broker_info = {
        "InstanceType": instance_type,
        "ClientSubnets": subnet_ids,
        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": volume_size}},
    }
    if sg_id:
        broker_info["SecurityGroups"] = [sg_id]
    return {
        "BrokerNodeGroupInfo": broker_info,
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": num_brokers,
    }


def _create_basic_cluster(ctx, msk, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                          name_prefix="cluster-", tags=None, teardown=None):
    """Create a PROVISIONED cluster (returns immediately, state CREATING). Registers a teardown that
    deletes the cluster and waits until it is gone. Returns (arn, name, subnet_ids, sg_id)."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    prov = _provisioned_body(subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version)
    # A VPC connection authenticates with SASL/IAM, and CreateVpcConnection refuses a cluster that
    # does not offer it ("SASL/IAM client authentication must be enabled for the cluster"), so a
    # plain cluster can never host the lifecycle under test. Multi-VPC private connectivity itself
    # cannot be requested here -- neither CreateCluster nor CreateClusterV2 models ConnectivityInfo
    # -- it is turned on with UpdateConnectivity once the cluster is ACTIVE (see _enable_multi_vpc).
    prov["ClientAuthentication"] = {"Sasl": {"Iam": {"Enabled": True}}}
    kwargs = {
        "ClusterName": name,
        "Provisioned": prov,
        "Tags": {"sim2real:managed": "true", **(tags or {})},
    }
    try:
        resp = msk.create_cluster_v2(**kwargs)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        raise AssertionError(
            f"could not create an MSK cluster for this check ({code}: {exc}); "
            f"network used: vpc subnets={subnet_ids} sg={sg_id}"
        ) from exc
    arn = resp["ClusterArn"]
    holder = {} if teardown is None else teardown
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn, holder))
    return arn, name, subnet_ids, sg_id


# Teardown budget for behavioral/kafka is 1800 s; the run's teardowns share one deadline in it.
_TEARDOWN_S = 1740.0


def _teardown_deadline(holder):
    return holder.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _delete_cluster_when_settled(msk, arn, holder):
    """Delete the cluster and wait until it is gone. DeleteCluster answers BadRequestException while the
    cluster is CREATING or UPDATING or still has a VPC connection, so it is reissued every 2 s."""
    deadline = _teardown_deadline(holder)
    while True:
        try:
            msk.delete_cluster(ClusterArn=arn)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while _err(lambda: msk.describe_cluster(ClusterArn=arn))[0] != "NotFoundException":
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still present at the teardown deadline")
        time.sleep(2)


def _wait_cluster_active(msk, arn, timeout_s=2700, interval_s=30):
    """Poll DescribeCluster (v1) until the cluster settles; Skip if it FAILED."""
    info = _poll_until(
        lambda: msk.describe_cluster(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


def _wait_cluster_gone(msk, arn, timeout_s=1800, interval_s=30):
    return _poll_until(
        lambda: _err(lambda: msk.describe_cluster(ClusterArn=arn)),
        lambda err: err[0] == "NotFoundException",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to be deleted",
    )


def _enable_multi_vpc(ctx, msk, cluster_arn, timeout_s=4800, interval_s=30):
    """Turn multi-VPC private connectivity on (IAM auth scheme) for an ACTIVE cluster.

    Required by CreateVpcConnection and NOT expressible at create time: ConnectivityInfo is a
    member of UpdateConnectivity only. Enabling it starts a rolling reboot of the broker nodes --
    AWS documents "up to 30 minutes or more", and no other update may run while it is in flight --
    so this polls the cluster OPERATION to completion rather than assuming the call is synchronous.
    A cluster left mid-update would fail CreateVpcConnection for a second, unrelated reason.

    The deadline is observed, not documented: a 2-broker UPDATE_CONNECTIVITY on AWS ran 52.6
    minutes, so this carries ~50% headroom over that. It is a ceiling, not a wait.
    """
    current_version = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]
    resp = msk.update_connectivity(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version,
        ConnectivityInfo={"VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}}},
    )
    op_arn = resp["ClusterOperationArn"]
    info = _poll_until(
        lambda: msk.describe_cluster_operation_v2(ClusterOperationArn=op_arn)["ClusterOperationInfo"],
        lambda i: i.get("OperationState", "").endswith(("COMPLETE", "COMPLETED", "FAILED")),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"UpdateConnectivity {op_arn} to settle",
    )
    state = info.get("OperationState")
    assert state == "UPDATE_COMPLETE", f"enabling multi-VPC connectivity ended {state}: {info.get('ErrorInfo')}"
    return info


def _wait_vpc_connection_state(msk, arn, states, timeout_s=600, interval_s=15):
    return _poll_until(
        lambda: msk.describe_vpc_connection(Arn=arn),
        lambda i: i.get("State") in states,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"vpc connection {arn} to reach {states}",
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcConnection drives CREATING -> AVAILABLE; DeleteVpcConnection removes it.

    The connection reaches AVAILABLE echoing its VpcId; after delete DescribeVpcConnection and a second
    DeleteVpcConnection fail with NotFoundException and its exact message rather than a silent success."""
    # An MSK cluster create (~30 min) followed by a multi-VPC connectivity enable (~30-60 min) and
    # the connection state poll realistically exceed 5400 s; both waits are MSK's own clocks.
    msk = ctx.client("kafka")
    # One teardown deadline per run, started by the first teardown that runs.
    teardown: dict = {}
    cluster_arn, _name, _subnets, _sg = _create_basic_cluster(
        ctx, msk, num_brokers=2, name_prefix="vpcconn-cluster-", teardown=teardown
    )
    _wait_cluster_active(msk, cluster_arn)
    _enable_multi_vpc(ctx, msk, cluster_arn)

    vpc_id, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    if not sg_id:
        raise AssertionError("no security group discoverable in the shared VPC")
    resp = msk.create_vpc_connection(
        TargetClusterArn=cluster_arn,
        Authentication="SASL_IAM",
        VpcId=vpc_id,
        ClientSubnets=subnet_ids,
        SecurityGroups=[sg_id],
        Tags={"sim2real:managed": "true"},
    )
    vpc_conn_arn = resp["VpcConnectionArn"]
    ctx.on_cleanup(lambda _a=vpc_conn_arn: _delete_vpc_connection_if_present(msk, _a, teardown))

    info = _wait_vpc_connection_state(msk, vpc_conn_arn, ("AVAILABLE", "FAILED"))
    assert info["State"] == "AVAILABLE", f"vpc connection did not reach AVAILABLE, got {info['State']}"
    assert info["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r} on the connection, got {info.get('VpcId')!r} (full={info})"

    msk.delete_vpc_connection(Arn=vpc_conn_arn)
    final = _poll_until(
        lambda: _err(lambda: msk.describe_vpc_connection(Arn=vpc_conn_arn)),
        lambda err: err[0] == "NotFoundException",
        timeout_s=600,
        interval_s=15,
        description="vpc connection to be deleted",
    )
    assert final == _NOT_FOUND, f"expected {_NOT_FOUND!r} reading a deleted vpc connection, got {final!r}"

    redelete_code = _err(lambda: msk.delete_vpc_connection(Arn=vpc_conn_arn))
    assert redelete_code == _NOT_FOUND, (
        f"deleting the already-deleted vpc connection {vpc_conn_arn} should report NotFoundException, "
        f"got {redelete_code!r}"
    )


def _delete_vpc_connection_if_present(msk, arn, holder):
    """Delete the VPC connection if run() left it, and wait until it is gone: the cluster delete that
    follows is refused while it remains."""
    deadline = _teardown_deadline(holder)
    try:
        msk.delete_vpc_connection(Arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
    while _err(lambda: msk.describe_vpc_connection(Arn=arn))[0] != "NotFoundException":
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC connection {arn} still present at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
