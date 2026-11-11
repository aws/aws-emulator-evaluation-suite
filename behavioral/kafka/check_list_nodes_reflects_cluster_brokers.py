"""list-nodes-reflects-cluster-brokers."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-nodes-reflects-cluster-brokers"
GROUP = 'read-paths'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the ClientError's (code, message). An accepted call fails the check."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was accepted; a ClientError refusal was expected")


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return True
        raise
    return False


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


_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


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
                          name_prefix="cluster-", tags=None):
    """Create a PROVISIONED cluster (returns immediately, state CREATING). Registers
    a DeleteCluster-and-wait teardown; the sim2real:managed tag marks it for cleanup
    if that wait is itself abandoned. Returns (arn, name, subnet_ids, sg_id)."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    kwargs = {
        "ClusterName": name,
        "Provisioned": _provisioned_body(
            subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version
        ),
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
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(msk, arn))
    return arn, name, subnet_ids, sg_id


def _wait_cluster_active(msk, arn, timeout_s=2700, interval_s=30):
    """Poll DescribeClusterV2 until the cluster settles; raise if it lands anywhere but ACTIVE."""
    info = _poll_until(
        lambda: msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


def _wait_cluster_gone(msk, arn, timeout_s=1800, interval_s=30):
    """Poll DescribeClusterV2 until arn answers NotFoundException."""
    return _poll_until(
        lambda: _gone(lambda: msk.describe_cluster_v2(ClusterArn=arn)),
        lambda gone: gone,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to be deleted",
    )


def _delete_cluster_and_wait(msk, arn):
    """Delete arn and wait for it to fully disappear, so the post-run account scan sees
    nothing left rather than a still-DELETING cluster (MSK teardown routinely exceeds the
    60s ctx.on_cleanup budget; the sim2real:managed tag on arn marks it for cleanup if
    this wait is itself abandoned)."""
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return
        raise
    _wait_cluster_gone(msk, arn)


def _shared_creating_cluster(ctx, msk):
    """The check's own CREATING cluster, provisioned once per check (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_shared_cluster"):
        arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="shared-")
        ctx._kafka_shared_cluster = arn
    return ctx._kafka_shared_cluster


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNodes enumerates broker nodes only once the service actually has them.

    A CREATING cluster is BadRequestException (not an empty list), an unknown one NotFoundException,
    and once ACTIVE ListNodes lists exactly the two configured brokers.
    """
    msk = ctx.client("kafka")
    arn = _shared_creating_cluster(ctx, msk)
    info = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
    assert info["State"] == "CREATING", f"expected CREATING, got {info['State']}"
    assert info["Provisioned"]["NumberOfBrokerNodes"] == 2, info

    err, err_message = _err(lambda: msk.list_nodes(ClusterArn=arn))
    assert err == "BadRequestException", f"expected BadRequestException while CREATING, got {err}"
    assert err_message == "You can't list the nodes for a cluster that is in the CREATING state.", (
        f"ListNodes message while CREATING: {err_message!r}"
    )

    ghost, ghost_message = _err(lambda: msk.list_nodes(ClusterArn=_bogus_cluster_arn(ctx)))
    assert ghost == "NotFoundException", f"ghost cluster: expected NotFoundException, got {ghost}"
    assert ghost_message == "The requested resource doesn\u2019t exist.", f"ghost cluster message: {ghost_message!r}"

    # DescribeCluster keeps reporting the configured broker count throughout.
    after = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["Provisioned"][
        "NumberOfBrokerNodes"
    ]
    assert after == 2, after

    active = _wait_cluster_active(msk, arn)
    assert active["Provisioned"]["NumberOfBrokerNodes"] == 2, active

    nodes = msk.list_nodes(ClusterArn=arn).get("NodeInfoList", [])
    assert len(nodes) == 2, f"expected ListNodes to reflect 2 broker nodes once ACTIVE, got {nodes}"
    broker_ids = sorted(int(n["BrokerNodeInfo"]["BrokerId"]) for n in nodes)
    assert broker_ids == [1, 2], f"expected broker IDs [1, 2], got {broker_ids}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
