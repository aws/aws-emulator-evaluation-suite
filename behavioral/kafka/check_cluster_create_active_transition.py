"""cluster-create-active-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-active-transition"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"
_CONFLICT = ("ConflictException", "A resource with this name already exists.")


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, so an over-permissive target fails as an acceptance
    rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


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
                          name_prefix="cluster-", tags=None):
    """Create a PROVISIONED cluster (returns immediately, state CREATING). Registers a
    DeleteCluster teardown that lets the cluster settle, deletes it and waits until it is
    gone. Returns (arn, name, subnet_ids, sg_id)."""
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
    def _cleanup():
        # DeleteCluster refuses a cluster that is still CREATING, so let it settle first; the
        # settle and deletion waits together stay inside the suite's 1800 s cleanup budget.
        deadline = time.monotonic() + 1740
        state = _poll_until(
            lambda: _describe_state(msk, arn),
            lambda state: state not in ("CREATING", "UPDATING"),
            timeout_s=max(deadline - time.monotonic() - 120, 60),
            interval_s=2,
            description=f"cluster {arn} to settle before teardown",
        )
        if state == "GONE":
            return
        if state != "DELETING":
            try:
                msk.delete_cluster(ClusterArn=arn)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                    raise
                return
        _wait_cluster_gone(msk, arn, timeout_s=max(deadline - time.monotonic(), 60), interval_s=2)

    ctx.on_cleanup(_cleanup)
    return arn, name, subnet_ids, sg_id


def _wait_cluster_active(msk, arn, timeout_s=2700, interval_s=30):
    """Poll DescribeCluster (v1) until the cluster settles; raise if it FAILED."""
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


def _describe_state(msk, arn):
    """DescribeCluster state, or "GONE" once the cluster no longer resolves."""
    try:
        return msk.describe_cluster(ClusterArn=arn)["ClusterInfo"].get("State")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return "GONE"
        raise


def _wait_cluster_gone(msk, arn, timeout_s=1800, interval_s=30):
    return _poll_until(
        lambda: _describe_state(msk, arn),
        lambda state: state == "GONE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to be deleted",
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster drives a PROVISIONED cluster CREATING -> ACTIVE with the requested broker count,
    and a second CreateCluster reusing the name is refused with ConflictException, leaving the original untouched.
    """
    msk = ctx.client("kafka")
    arn, name, subnet_ids, sg_id = _create_basic_cluster(ctx, msk, num_brokers=2, name_prefix="cluster-active-")

    info = _wait_cluster_active(msk, arn)
    assert info["State"] == "ACTIVE", info
    assert info["ClusterName"] == name, info
    assert info["NumberOfBrokerNodes"] == 2, info

    dup = _err(
        lambda: msk.create_cluster(
            ClusterName=name,
            KafkaVersion=_DEFAULT_KAFKA_VERSION,
            NumberOfBrokerNodes=2,
            BrokerNodeGroupInfo={
                "InstanceType": _PROVISIONED_INSTANCE_TYPE,
                "ClientSubnets": subnet_ids,
                "SecurityGroups": [sg_id] if sg_id else [],
            },
        )
    )
    assert dup == _CONFLICT, f"expected ConflictException for duplicate name, got {dup!r}"

    # Effect absent: the rejected duplicate did not disturb the original cluster or spawn a
    # second one under the same name.
    after = msk.describe_cluster(ClusterArn=arn)["ClusterInfo"]
    assert after["ClusterArn"] == arn, after
    assert after["State"] == "ACTIVE", after
    assert after["NumberOfBrokerNodes"] == 2, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
