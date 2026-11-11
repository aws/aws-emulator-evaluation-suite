"""broker-count-decrease-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "broker-count-decrease-rejected"
GROUP = 'cluster-state-guards'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _err(fn):
    """Call fn(); return the ClientError's (code, message). An accepted call fails the check."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was accepted; a ClientError refusal was expected")


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


def _wait_cluster_active(ctx, msk, arn):
    """Wait until the cluster is ACTIVE and return its ClusterInfo. MSK PROVISIONED cluster creation
    routinely takes 15-30 minutes and a 4-broker/2-AZ cluster can still be CREATING at 1800 s, so the
    budget carries headroom; on timeout it raises with the last state seen."""
    budget_s = 3000
    interval_s = 2
    deadline = time.monotonic() + (budget_s if ctx.time_left() is None else min(budget_s, ctx.time_left()))
    last = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last == "ACTIVE":
            return info
        if last == "FAILED":
            raise AssertionError("cluster reached FAILED instead of ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster not ACTIVE within {budget_s}s (last state {last}); "
        "MSK provisioning exceeds the per-check budget"
    )


def _wait_operation_state(ctx, msk, op_arn, states):
    """Poll DescribeClusterOperation until OperationState is one of states. Real MSK
    broker-count scale operations run on the same order of magnitude as cluster
    creation, so the budget mirrors _wait_cluster_active's. Raises on timeout
    instead of returning a non-terminal state."""
    budget_s = 3000
    interval_s = 2
    deadline = time.monotonic() + (budget_s if ctx.time_left() is None else min(budget_s, ctx.time_left()))
    last = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        last = info.get("OperationState")
        if last in states:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation not in {sorted(states)} within {budget_s}s (last {last})")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateBrokerCount below the current count fails with BadRequestException and its exact message and
    leaves the cluster ACTIVE at 4 brokers and the same version; a scale-out to 6 on the same cluster then
    completes."""
    msk = ctx.client("kafka")
    # 2 client-subnet AZs => MSK requires NumberOfBrokerNodes to be a multiple of 2, for both
    # CreateClusterV2 (real AWS rejects num_brokers=3 outright with BadRequestException:
    # "target number of broker nodes must be a multiple of the number of Availability
    # Zones") and, per the docs, UpdateBrokerCount's target. Starting at 4 and decreasing to
    # 2 keeps the decrease target ITSELF a valid multiple, so a rejection can only be the
    # "scale-in is not supported" rule under test -- not a confound with the AZ-multiple rule.
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=4, name_prefix="brokerdec-")
    info = _wait_cluster_active(ctx, msk, arn)
    version = info["CurrentVersion"]

    code, message = _err(
        lambda: msk.update_broker_count(
            ClusterArn=arn, CurrentVersion=version, TargetNumberOfBrokerNodes=2
        )
    )
    assert code == "BadRequestException", f"broker-count decrease must be BadRequestException, got {code}"
    expected = (
        "Amazon MSK cannot proceed with decreasing the cluster's broker count. Make sure that at "
        "least one broker in each Availability Zone has no user partitions and try again. Allow "
        "five minutes after partition reassignments."
    )
    assert message == expected, f"broker-count decrease message: {message!r}"

    # Independent read at the destination (DescribeClusterV2, a different operation than
    # UpdateBrokerCount): the rejection must mean nothing changed, not merely that the
    # mutating call's own response was an error.
    after_reject = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
    assert after_reject["State"] == "ACTIVE", (
        f"cluster must remain ACTIVE after a rejected decrease, got {after_reject['State']}"
    )
    assert after_reject["Provisioned"]["NumberOfBrokerNodes"] == 4, (
        "broker count must be unchanged by a rejected decrease, got "
        f"{after_reject['Provisioned']['NumberOfBrokerNodes']}"
    )
    assert after_reject["CurrentVersion"] == version, (
        "CurrentVersion must be unchanged by a rejected decrease (no ClusterOperation "
        f"may have been queued): got {after_reject['CurrentVersion']}"
    )

    # Positive control: the SAME API, a valid scale-OUT (also a multiple of 2) on the SAME
    # cluster, must succeed.
    increase = msk.update_broker_count(
        ClusterArn=arn,
        CurrentVersion=after_reject["CurrentVersion"],
        TargetNumberOfBrokerNodes=6,
    )
    op_arn = increase["ClusterOperationArn"]
    op_info = _wait_operation_state(ctx, msk, op_arn, {"UPDATE_COMPLETE", "UPDATE_FAILED"})
    assert op_info["OperationState"] == "UPDATE_COMPLETE", (
        f"positive-control scale-out ended in {op_info['OperationState']}"
    )
    final = _wait_cluster_active(ctx, msk, arn)
    assert final["Provisioned"]["NumberOfBrokerNodes"] == 6, (
        f"positive control must land: expected 6 brokers, got {final['Provisioned']['NumberOfBrokerNodes']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
