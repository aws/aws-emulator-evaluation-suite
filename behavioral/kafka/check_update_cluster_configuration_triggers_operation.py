"""update-cluster-configuration-triggers-operation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-cluster-configuration-triggers-operation"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


# MSK's message for a cluster ARN that resolves to nothing (U+2019 apostrophe).
_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


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
    """The run's shared network (ctx.network()): its VPC, two of its subnets in distinct
    availability zones, and the VPC's default security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:2], net.security_group_id


def _create_creating_cluster(ctx, msk):
    """Create a real, minimal MSK cluster and return (arn, current_version) WITHOUT waiting
    for it to become ACTIVE: a real, resolvable ClusterArn is all the reference-resolution
    question below needs. Real MSK refuses DeleteCluster while the cluster is CREATING, so the
    check settles it with _settle_for_delete before it returns; the registered DeleteCluster
    cleanup then succeeds.
    """
    _, subnets, sg_id = _discover_network(ctx, minimum_subnets=2)
    name = ctx.unique_name("sim2real-behav-cfgop-")
    broker_info = {
        "InstanceType": "kafka.t3.small",
        "ClientSubnets": subnets,
        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
    }
    if sg_id:
        broker_info["SecurityGroups"] = [sg_id]
    resp = msk.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": broker_info,
            "KafkaVersion": "3.9.x",
            "NumberOfBrokerNodes": 2,
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(msk, arn))
    version = msk.describe_cluster(ClusterArn=arn)["ClusterInfo"]["CurrentVersion"]
    return arn, version


def _delete_cluster(msk, arn):
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _settle_for_delete(msk, arn, timeout_s=2700, interval_s=30):
    """Poll until the cluster leaves CREATING (DeleteCluster refuses a CREATING cluster)."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = msk.describe_cluster(ClusterArn=arn)["ClusterInfo"]["State"]
        if state != "CREATING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} still {state} after {timeout_s}s; it cannot be deleted")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateClusterConfiguration fails with NotFoundException for a missing cluster with a real or made-up
    configuration, while on a real CREATING cluster it fails with BadRequestException and the ACTIVE-state
    message."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-cfg-")
    cfg = msk.create_configuration(
        Name=name, KafkaVersions=["3.9.x"], ServerProperties=b"auto.create.topics.enable=false"
    )
    ctx.on_cleanup(lambda: msk.delete_configuration(Arn=cfg["Arn"]))
    assert cfg["LatestRevision"]["Revision"] == 1, cfg

    ghost = _bogus_cluster_arn(ctx)
    err = _err(
        lambda: msk.update_cluster_configuration(
            ClusterArn=ghost,
            CurrentVersion="1",
            ConfigurationInfo={"Arn": cfg["Arn"], "Revision": 1},
        )
    )
    assert err == _NOT_FOUND, f"real config on ghost cluster: expected {_NOT_FOUND!r}, got {err!r}"

    ghost_cfg_arn = cfg["Arn"].rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000-9"
    cfg_err = _err(
        lambda: msk.update_cluster_configuration(
            ClusterArn=ghost,
            CurrentVersion="1",
            ConfigurationInfo={"Arn": ghost_cfg_arn, "Revision": 1},
        )
    )
    assert cfg_err == _NOT_FOUND, f"ghost config on ghost cluster: expected {_NOT_FOUND!r}, got {cfg_err!r}"

    listed = _err(lambda: msk.list_cluster_operations_v2(ClusterArn=ghost))
    assert listed == _NOT_FOUND, f"ListClusterOperationsV2: expected {_NOT_FOUND!r}, got {listed!r}"

    real_arn, real_version = _create_creating_cluster(ctx, msk)

    real_err = _err(
        lambda: msk.update_cluster_configuration(
            ClusterArn=real_arn,
            CurrentVersion=real_version,
            ConfigurationInfo={"Arn": ghost_cfg_arn, "Revision": 1},
        )
    )
    # The real cluster is still CREATING, so MSK refuses on its state, not on a missing cluster.
    expected_state_refusal = (
        "BadRequestException",
        "This operation is only valid for resources that are in one of the following states :[ACTIVE]",
    )
    assert real_err == expected_state_refusal, (
        "ghost config on a REAL cluster: a target resolving the cluster and config references "
        f"independently must refuse for a reason other than cluster-not-found: expected "
        f"{expected_state_refusal!r}, got {real_err!r}"
    )

    ops_resp = msk.list_cluster_operations_v2(ClusterArn=real_arn)
    assert "ClusterOperationInfoList" in ops_resp, (
        f"ListClusterOperationsV2 on a real (if still-provisioning) cluster must succeed, not 404: {ops_resp}"
    )

    _settle_for_delete(msk, real_arn)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
