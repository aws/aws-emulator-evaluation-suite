"""topic-partition-decrease-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-partition-decrease-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _describe_outcome(fn):
    """Call a Describe*; return the resource's Status on success, or its (code, message) refusal."""
    try:
        return fn().get("Status") or "PRESENT"
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


def _delete_tolerating_absent(fn):
    """Teardown delete that tolerates a resource the check already removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


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
    DeleteCluster teardown (a still-CREATING cluster can't be deleted inline; the
    sim2real:managed tag marks it for cleanup). Returns (arn, name, subnet_ids, sg_id)."""
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
    ctx.on_cleanup(lambda: _delete_tolerating_absent(lambda: msk.delete_cluster(ClusterArn=arn)))
    return arn, name, subnet_ids, sg_id


def _wait_cluster_active(msk, arn, timeout_s=2700, interval_s=30):
    """Poll DescribeCluster (v1) until the cluster settles; Skip if it FAILED."""
    info = _poll_until(
        lambda: msk.describe_cluster(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


def _wait_cluster_gone(msk, arn, timeout_s=1800, interval_s=30):
    return _poll_until(
        lambda: _describe_outcome(lambda: msk.describe_cluster(ClusterArn=arn)["ClusterInfo"]),
        lambda out: isinstance(out, tuple) and out[0] == "NotFoundException",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to be deleted",
    )

def _wait_topic_active(msk, cluster_arn, topic_name, timeout_s=300, interval_s=5):
    return _poll_until(
        lambda: msk.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name),
        lambda d: d.get("Status") == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"topic {topic_name} to become ACTIVE",
    )


def _active_cluster(ctx, msk, name_prefix, num_brokers=2):
    """Provision a PROVISIONED cluster and wait for ACTIVE (slow, but always runs)."""
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=num_brokers, name_prefix=name_prefix)
    _wait_cluster_active(msk, arn)
    return arn


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTopic must reject a PartitionCount decrease.

    After a legitimate increase succeeds (positive control), a shrink is BadRequestException and
    leaves the topic's partition count unchanged.
    """
    msk = ctx.client("kafka")
    cluster_arn = _active_cluster(ctx, msk, "topic-shrink-cluster-", num_brokers=2)
    topic_name = ctx.unique_name("sim2real-behav-topic-shrink-")

    msk.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=4, ReplicationFactor=1
    )
    ctx.on_cleanup(lambda: _delete_tolerating_absent(lambda: msk.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)))
    _wait_topic_active(msk, cluster_arn, topic_name)

    # Positive control: a legitimate increase succeeds, confirmed by an independent read.
    msk.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=6)
    _wait_topic_active(msk, cluster_arn, topic_name)
    grown = msk.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    assert grown["PartitionCount"] == 6, (
        f"positive control failed: expected PartitionCount 6 after a legitimate increase, "
        f"got {grown['PartitionCount']!r}"
    )

    # Negative: a decrease is rejected with the specific error.
    err = _err(
        lambda: msk.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=2)
    )
    expected = (
        "BadRequestException",
        "Topic currently has 6 partitions, which is higher than the requested 2.",
    )
    assert err == expected, f"partition decrease: expected {expected!r}, got {err!r}"

    # Effect absent: an independent read shows the partition count unchanged by the rejected call.
    unaffected = msk.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    assert unaffected["PartitionCount"] == 6, (
        f"partition count changed despite UpdateTopic rejecting the decrease: "
        f"{unaffected['PartitionCount']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
