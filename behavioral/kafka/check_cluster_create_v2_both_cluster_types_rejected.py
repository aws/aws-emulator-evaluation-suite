"""cluster-create-v2-both-cluster-types-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-v2-both-cluster-types-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_ONE_CLUSTER_TYPE_MESSAGE = "You can specify only one cluster type, either provisioned or serverless."

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


def _cleanup_by_name(msk, name):
    """Teardown for the case create_cluster_v2 unexpectedly succeeds."""
    clusters = msk.list_clusters_v2(ClusterNameFilter=name)["ClusterInfoList"]
    for cluster in clusters:
        try:
            msk.delete_cluster(ClusterArn=cluster["ClusterArn"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateClusterV2 with BOTH Provisioned and Serverless bodies -> BadRequestException.

    The two are mutually exclusive; accepting both would be overly permissive.
    """
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-bothtype-cluster-")
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    ctx.on_cleanup(lambda: _cleanup_by_name(msk, name))

    code, message = _err(
        lambda: msk.create_cluster_v2(
            ClusterName=name,
            Provisioned=_provisioned_body(subnet_ids, sg_id),
            Serverless={
                "VpcConfigs": [{"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}],
                "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
            },
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == _ONE_CLUSTER_TYPE_MESSAGE, message
    listed = msk.list_clusters_v2(ClusterNameFilter=name)["ClusterInfoList"]
    assert listed == [], f"expected no cluster named {name!r} after the rejected call, got {listed!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
