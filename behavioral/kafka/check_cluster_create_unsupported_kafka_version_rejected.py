"""cluster-create-unsupported-kafka-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-unsupported-kafka-version-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_UNSUPPORTED_VERSION_MESSAGE = (
    "Standard instance types are not supported for Kafka version 9.9.9. Valid values: ["
    "3.8.x, 3.8.x.kraft, 3.9.x, 3.9.x.kraft, 4.0.x.kraft, 4.1.x.kraft]"
)

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A KafkaVersion that MSK does not support -> BadRequestException."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-badver-cluster-")
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)

    code, message = _err(
        lambda: msk.create_cluster_v2(
            ClusterName=name,
            Provisioned=_provisioned_body(subnet_ids, sg_id, kafka_version="9.9.9"),
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == _UNSUPPORTED_VERSION_MESSAGE, message
    # Independent read at the destination: the rejected create must not have left a cluster behind.
    listed = msk.list_clusters_v2(ClusterNameFilter=name)["ClusterInfoList"]
    assert listed == [], f"expected no cluster named {name!r} after the rejected create, got {listed}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
