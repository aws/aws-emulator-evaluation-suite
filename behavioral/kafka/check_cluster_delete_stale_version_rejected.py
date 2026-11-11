"""cluster-delete-stale-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-delete-stale-version-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise.
    For a probe polled toward a not-found terminal state, where a plain success is a normal
    transient reading, not a defect."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return True
        raise
    return False


def _expect_rejected(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


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
    """Create a PROVISIONED cluster (returns immediately, state CREATING). Registers
    DeleteCluster teardown that waits for the cluster to settle. Returns (arn, name, subnet_ids, sg_id)."""
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
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn))
    return arn, name, subnet_ids, sg_id


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=30.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state == "DELETING":
                return
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it cannot be deleted")
        time.sleep(interval_s)


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
        lambda: _gone(lambda: msk.describe_cluster(ClusterArn=arn)),
        lambda gone: gone,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to be deleted",
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster with a stale CurrentVersion fails with BadRequestException and leaves the cluster
    ACTIVE at its version; with the real version it succeeds, and the cluster then answers
    NotFoundException to Describe and to a second Delete."""
    msk = ctx.client("kafka")
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="cluster-verlock-")
    active = _wait_cluster_active(msk, arn)
    real_version = active["CurrentVersion"]

    code, message = _expect_rejected(
        lambda: msk.delete_cluster(ClusterArn=arn, CurrentVersion="bogus-stale-version")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "One or more of the parameters are not valid.", f"stale-version delete message: {message!r}"

    still = msk.describe_cluster(ClusterArn=arn)["ClusterInfo"]
    assert still["State"] == "ACTIVE", still
    assert still["CurrentVersion"] == real_version, (
        f"a rejected delete must not advance CurrentVersion: expected {real_version!r}, "
        f"got {still['CurrentVersion']!r}"
    )

    # Restore: the identical call, now carrying the real CurrentVersion, succeeds.
    msk.delete_cluster(ClusterArn=arn, CurrentVersion=real_version)
    _wait_cluster_gone(msk, arn)
    post_code, post_message = _expect_rejected(lambda: msk.describe_cluster(ClusterArn=arn))
    assert post_code == "NotFoundException", (
        f"cluster must be gone after a correctly-versioned delete, got {post_code!r}"
    )
    assert post_message == "The requested resource doesn\u2019t exist.", f"DescribeCluster message: {post_message!r}"

    # A mutation on the now-dead id (a second delete) must also fail, not resurrect anything.
    double_code, double_message = _expect_rejected(lambda: msk.delete_cluster(ClusterArn=arn))
    assert double_code == "NotFoundException", (
        f"delete on an already-gone cluster must be NotFoundException, got {double_code!r}"
    )
    assert double_message == "The requested resource doesn\u2019t exist.", f"second DeleteCluster message: {double_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
