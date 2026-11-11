"""vpcconnection-requires-multi-vpc-enabled-cluster."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpcconnection-requires-multi-vpc-enabled-cluster"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_CLUSTER_STATE_REFUSAL = (
    "BadRequestException",
    "Invalid cluster state. To create, delete or reject a VPC connection, your cluster must be in "
    "one of these states: ACTIVE, UPDATING, MAINTENANCE, HEALING, or REBOOTING_BROKER.",
)


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected SUCCESS raises with the actual result, because an emulator ACCEPTING a call real
    AWS refuses is the strongest signal available and must not be reported as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _require_security_group(ctx):
    """A real security group id, or skip the check if none is visible."""
    _vpc_id, _subnets, sg_id = _create_cluster_network(ctx, num_subnets=2)
    if not sg_id:
        raise AssertionError("no security group discoverable in the shared VPC")
    return sg_id


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
    DeleteCluster teardown; a still-CREATING cluster can't be deleted, so run() waits it out
    first. Returns (arn, name, subnet_ids, sg_id)."""
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


def _shared_creating_cluster(ctx, msk):
    """The check's own CREATING cluster, provisioned once per check (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_shared_cluster"):
        arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="shared-")
        ctx._kafka_shared_cluster = arn
    return ctx._kafka_shared_cluster


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcConnection is refused for a CREATING cluster by the cluster-state gate itself.

    A real VpcId and a nonexistent one both get the same BadRequestException "Invalid cluster state.
    ..." message, so readiness is checked before the VpcId, and nothing is registered either way.
    """
    msk = ctx.client("kafka")
    arn = _shared_creating_cluster(ctx, msk)

    try:
        vpc_id, client_subnets, _sg = _create_cluster_network(ctx, num_subnets=2)
        client_sg = _require_security_group(ctx)

        not_enabled = _err(
            lambda: msk.create_vpc_connection(
                TargetClusterArn=arn,
                Authentication="SASL_IAM",
                VpcId=vpc_id,
                ClientSubnets=client_subnets,
                SecurityGroups=[client_sg],
            )
        )
        assert not_enabled == _CLUSTER_STATE_REFUSAL, f"expected {_CLUSTER_STATE_REFUSAL!r}, got {not_enabled!r}"

        bogus_vpc = _err(
            lambda: msk.create_vpc_connection(
                TargetClusterArn=arn,
                Authentication="SASL_IAM",
                VpcId="vpc-00000000deadbeef",
                ClientSubnets=client_subnets,
                SecurityGroups=[client_sg],
            )
        )
        assert bogus_vpc == _CLUSTER_STATE_REFUSAL, f"expected {_CLUSTER_STATE_REFUSAL!r}, got {bogus_vpc!r}"

        # Nothing may have been registered against the cluster.
        listed = msk.list_client_vpc_connections(ClusterArn=arn)["ClientVpcConnections"]
        assert listed == [], listed
    finally:
        _wait_until_deletable(msk, arn)


def _wait_until_deletable(msk, arn, *, timeout_s=3600, interval_s=30.0):
    """Poll until the cluster leaves CREATING, so the registered DeleteCluster teardown is accepted
    (AWS refuses DeleteCluster while a cluster is CREATING). Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        if state != "CREATING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} still {state!r} after {timeout_s}s; DeleteCluster would be refused")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
