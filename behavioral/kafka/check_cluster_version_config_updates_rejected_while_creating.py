"""cluster-version-config-updates-rejected-while-creating."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-version-config-updates-rejected-while-creating"
GROUP = 'cluster-state-guards'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.
    A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_DEFAULT_KAFKA_VERSION = "3.8.x"
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


def _shared_creating_cluster(ctx, msk):
    """The check's own CREATING cluster, provisioned once per check (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_shared_cluster"):
        arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="shared-")
        ctx._kafka_shared_cluster = arn
    return ctx._kafka_shared_cluster


def _create_test_configuration(ctx, msk, name_prefix="config-",
                               server_properties=b"num.partitions=1\n", kafka_versions=None):
    """Create an MSK configuration; register teardown. Returns (arn, name)."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    resp = msk.create_configuration(
        Name=name,
        Description="behavioral test configuration",
        KafkaVersions=kafka_versions or [_DEFAULT_KAFKA_VERSION],
        ServerProperties=server_properties,
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda: msk.delete_configuration(Arn=arn))
    return arn, name


def _cluster_current_version(msk, cluster_arn):
    return msk.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]


def _cluster_state(msk, cluster_arn):
    return msk.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]


STATE_REFUSAL_CODES = (
    "BadRequestException",
    "ClusterStateUnknownException",
    "InternalServerErrorException",
)
_STATE_REFUSAL = (
    "BadRequestException",
    "This operation is only valid for resources that are in one of the following states :[ACTIVE]",
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While CREATING, UpdateClusterConfiguration and UpdateConnectivity fail with BadRequestException and the
    ACTIVE-state message and UpdateClusterKafkaVersion with one of STATE_REFUSAL_CODES (BadRequestException
    with the same message); the cluster stays CREATING at its version."""
    msk = ctx.client("kafka")
    arn = _shared_creating_cluster(ctx, msk)
    version = _cluster_current_version(msk, arn)
    config_arn, _cfg_name = _create_test_configuration(ctx, msk, name_prefix="guard-config-")

    codes = {
        "UpdateClusterConfiguration": _err(
            lambda: msk.update_cluster_configuration(
                ClusterArn=arn,
                CurrentVersion=version,
                ConfigurationInfo={"Arn": config_arn, "Revision": 1},
            )
        ),
        "UpdateConnectivity": _err(
            lambda: msk.update_connectivity(
                ClusterArn=arn,
                CurrentVersion=version,
                ConnectivityInfo={"PublicAccess": {"Type": "DISABLED"}},
            )
        ),
    }

    bad = {op: code for op, code in codes.items() if code != _STATE_REFUSAL}
    assert not bad, f"expected {_STATE_REFUSAL!r} from CREATING state, got {bad}"

    upgrade_code, upgrade_message = _err(
        lambda: msk.update_cluster_kafka_version(
            ClusterArn=arn, CurrentVersion=version, TargetKafkaVersion="3.9.x"
        )
    )
    # MSK is not deterministic about which state error it returns for an upgrade of a
    # CREATING cluster (it varies with provisioning progress); any refusal is correct.
    assert upgrade_code in STATE_REFUSAL_CODES, (
        f"UpdateClusterKafkaVersion must be refused while CREATING, got {upgrade_code}"
    )
    if upgrade_code == "BadRequestException":
        assert upgrade_message == _STATE_REFUSAL[1], f"UpdateClusterKafkaVersion message: {upgrade_message!r}"

    # The refused upgrade must not have moved the cluster or its version.
    assert _cluster_state(msk, arn) == "CREATING"
    assert _cluster_current_version(msk, arn) == version

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
