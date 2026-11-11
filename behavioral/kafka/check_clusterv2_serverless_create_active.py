"""clusterv2-serverless-create-active."""

from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "clusterv2-serverless-create-active"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


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
    """The run's shared network: its VPC, up to three subnets in distinct AZs, and the default
    security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:3], net.security_group_id


def _create_cluster_network(ctx, num_subnets=2):
    """The shared network, memoized on ctx."""
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


def _wait_cluster_v2_active(msk, arn, timeout_s=2700, interval_s=20):
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateClusterV2 with a Serverless body creates a SERVERLESS cluster that reaches ACTIVE.

    ClusterType must be SERVERLESS at create time and once ACTIVE; with no brokers to provision,
    the CREATING -> ACTIVE transition completes in minutes.
    """
    msk = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    name = ctx.unique_name("sim2real-behav-serverless-")
    resp = msk.create_cluster_v2(
        ClusterName=name,
        Serverless={
            "VpcConfigs": [{"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id] if sg_id else []}],
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn))
    assert resp["ClusterType"] == "SERVERLESS", resp

    info = _wait_cluster_v2_active(msk, arn)
    assert info["State"] == "ACTIVE", info
    assert info["ClusterType"] == "SERVERLESS", info
    assert "Serverless" in info, sorted(info)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
