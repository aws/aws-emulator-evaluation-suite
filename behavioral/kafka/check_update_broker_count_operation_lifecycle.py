"""update-broker-count-operation-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-broker-count-operation-lifecycle"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _err(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


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
    """The discovered network, memoized on ctx."""
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
    """Wait until the cluster is ACTIVE and return ClusterInfo.

    MSK provisioned clusters routinely take 20-30+ minutes to leave CREATING.
    """
    budget_s = 2700
    interval_s = 30
    deadline = time.monotonic() + budget_s
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
    """Poll DescribeClusterOperation until OperationState is one of states; raises on timeout.

    A broker-count scaling operation can take up to ~30 minutes.
    """
    budget_s = 1800
    interval_s = 20
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        last = info.get("OperationState")
        if last in states:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation not in {sorted(states)} within {budget_s}s (last {last})")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBrokerCount returns a ClusterOperationArn whose operation reaches UPDATE_COMPLETE, and
    only then does DescribeClusterV2 report the new NumberOfBrokerNodes: scaling is async."""
    msk = ctx.client("kafka")
    arn, _name, subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=2, name_prefix="brokercount-")
    info = _wait_cluster_active(ctx, msk, arn)

    # MSK requires the target broker count to be a multiple of the number of AZs
    # (client subnets); with 2 subnets, 2 -> 4 is the minimal valid scale-out step.
    target_brokers = 2 * len(subnets)
    resp = msk.update_broker_count(
        ClusterArn=arn, CurrentVersion=info["CurrentVersion"], TargetNumberOfBrokerNodes=target_brokers
    )
    op_arn = resp["ClusterOperationArn"]

    op_info = _wait_operation_state(ctx, msk, op_arn, {"UPDATE_COMPLETE", "UPDATE_FAILED"})
    assert op_info["OperationState"] == "UPDATE_COMPLETE", f"operation ended in {op_info['OperationState']}"

    final = _wait_cluster_active(ctx, msk, arn)
    assert final["Provisioned"]["NumberOfBrokerNodes"] == target_brokers, (
        f"expected {target_brokers} brokers, got {final['Provisioned']['NumberOfBrokerNodes']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
