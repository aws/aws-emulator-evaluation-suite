"""reboot-broker-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reboot-broker-state-transition"
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
    """Wait until the cluster is ACTIVE. Real MSK provisioning of a 2-broker
    PROVISIONED cluster routinely takes 20-30 minutes; a target that reaches ACTIVE
    sooner ends the same loop sooner. Returns ClusterInfo."""
    budget_s = 1800
    interval_s = 20
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
    """Poll DescribeClusterOperation until OperationState is one of states; fail on timeout.
    A real RebootBroker on a 2-broker cluster reboots brokers one at a time to avoid a full
    outage, so this can take as long as cluster creation itself."""
    budget_s = 1500
    interval_s = 15
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        last = info.get("OperationState")
        if last in states:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation not in {sorted(states)} within {budget_s}s (last {last})")


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebootBroker drives an async ClusterOperation and returns the cluster to ACTIVE.

    The returned ClusterOperationArn walks to REBOOT_COMPLETE and the cluster is ACTIVE again; one
    broker id from ListNodes is rebooted, since RebootBroker takes exactly one id per call.
    """
    msk = ctx.client("kafka")
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=2, name_prefix="reboot-")
    _wait_cluster_active(ctx, msk, arn)

    nodes = msk.list_nodes(ClusterArn=arn)["NodeInfoList"]
    broker_ids = [
        str(int(n["BrokerNodeInfo"]["BrokerId"])) for n in nodes if "BrokerNodeInfo" in n
    ]
    assert len(broker_ids) == 2, f"expected the 2 requested broker nodes, got {nodes}"

    resp = msk.reboot_broker(ClusterArn=arn, BrokerIds=[broker_ids[0]])
    op_arn = resp["ClusterOperationArn"]

    # A RebootBroker-triggered ClusterOperation terminates in REBOOT_COMPLETE, not UPDATE_COMPLETE
    # -- UPDATE_COMPLETE/UPDATE_FAILED are the terminal states for the other operation kinds (broker
    # count/version/etc).
    op_info = _wait_operation_state(ctx, msk, op_arn, {"REBOOT_COMPLETE", "REBOOT_FAILED"})
    assert op_info["OperationState"] == "REBOOT_COMPLETE", (
        f"reboot operation ended in {op_info['OperationState']}"
    )

    final = _wait_cluster_active(ctx, msk, arn)
    assert final["State"] == "ACTIVE", final["State"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
