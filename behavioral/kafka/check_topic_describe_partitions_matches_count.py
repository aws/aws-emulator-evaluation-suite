"""topic-describe-partitions-matches-count."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-describe-partitions-matches-count"
GROUP = 'data-plane'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return True
        raise
    return False


def _refusal(fn):
    """(code, message) of the ClientError fn raises; ("ok", None) while the call still succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "ok", None


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
        lambda: _gone(lambda: msk.describe_cluster(ClusterArn=arn)),
        lambda gone: gone,
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


def _delete_topic(msk, cluster_arn, topic_name, timeout_s=120.0):
    """DeleteTopic, retried while MSK refuses a topic still CREATING (BadRequestException); not-found
    is done, anything else (or the deadline) raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            msk.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _active_cluster(ctx, msk, name_prefix, num_brokers=2):
    """Provision a PROVISIONED cluster and wait for ACTIVE (slow, but always runs)."""
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=num_brokers, name_prefix=name_prefix)
    _wait_cluster_active(msk, arn)
    return arn


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTopicPartitions reports exactly PartitionCount partitions, ids 0..N-1."""
    msk = ctx.client("kafka")
    cluster_arn = _active_cluster(ctx, msk, "topic-parts-cluster-", num_brokers=2)
    topic_name = ctx.unique_name("sim2real-behav-topic-parts-")

    msk.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=4, ReplicationFactor=2
    )
    ctx.on_cleanup(lambda: _delete_topic(msk, cluster_arn, topic_name))
    _wait_topic_active(msk, cluster_arn, topic_name)

    partitions = msk.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=topic_name)["Partitions"]
    assert len(partitions) == 4, f"expected 4 partitions, describe_topic_partitions returned {len(partitions)}: {partitions}"
    ids = sorted(p["Partition"] for p in partitions)
    assert ids == [0, 1, 2, 3], f"expected partition ids [0, 1, 2, 3], got {ids}: {partitions}"

    msk.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    final = _poll_until(
        lambda: _refusal(lambda: msk.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)),
        lambda answer: answer[0] == "NotFoundException",
        timeout_s=120,
        interval_s=3,
        description=f"topic {topic_name} to be deleted",
    )
    assert final == ("NotFoundException", "The requested resource doesn\u2019t exist."), (
        f"expected NotFoundException after delete_topic, describe_topic returned {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
