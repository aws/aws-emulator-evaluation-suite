"""cluster-duplicate-name-conflict-across-api-versions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-duplicate-name-conflict-across-api-versions"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_NAME_CONFLICT = ("ConflictException", "A resource with this name already exists.")

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError; success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


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
    teardown that waits for the cluster to leave CREATING (MSK refuses DeleteCluster
    until then) and deletes it. Returns (arn, name, subnet_ids, sg_id)."""
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


def _wait_cluster_settled(msk, arn, timeout_s=2700, interval_s=30):
    """Wait (bounded) until the cluster leaves CREATING; return its state, or None once gone."""
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
        if time.monotonic() > deadline:
            raise AssertionError(f"cluster {arn} still CREATING after {timeout_s}s; cannot delete it")
        time.sleep(interval_s)


def _delete_cluster_when_settled(msk, arn):
    """Teardown: delete the cluster once it has left CREATING (MSK refuses it before)."""
    if _wait_cluster_settled(msk, arn, timeout_s=600) in (None, "DELETING"):
        return
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A used ClusterName conflicts via both CreateClusterV2 and CreateCluster: the v1 create
    rejects a v2-created name with ConflictException, and no rejected attempt adds a cluster."""
    msk = ctx.client("kafka")
    arn, name, subnet_ids, sg_id = _create_basic_cluster(ctx, msk)
    try:
        body = _provisioned_body(subnet_ids, sg_id)

        v2_code = _err(
            lambda: msk.create_cluster_v2(ClusterName=name, Provisioned=body)
        )
        assert v2_code == _NAME_CONFLICT, f"expected ConflictException from v2, got {v2_code}"

        v1_code = _err(
            lambda: msk.create_cluster(
                ClusterName=name,
                BrokerNodeGroupInfo=body["BrokerNodeGroupInfo"],
                KafkaVersion=body["KafkaVersion"],
                NumberOfBrokerNodes=body["NumberOfBrokerNodes"],
            )
        )
        assert v1_code == _NAME_CONFLICT, f"expected ConflictException from v1, got {v1_code}"

        listed = msk.list_clusters_v2(ClusterNameFilter=name)["ClusterInfoList"]
        assert len(listed) == 1, (
            f"expected exactly one cluster named {name} after two rejected duplicates, "
            f"found {len(listed)}"
        )
        assert listed[0]["ClusterArn"] == arn, (
            f"expected the original cluster arn {arn}, ListClustersV2 shows {listed[0]['ClusterArn']}"
        )
    finally:
        # MSK refuses DeleteCluster while CREATING; let the cluster settle so the
        # registered teardown can delete it.
        _wait_cluster_settled(msk, arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
