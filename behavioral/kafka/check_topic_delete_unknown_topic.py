"""topic-delete-unknown-topic."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-delete-unknown-topic"
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


def _err_pair(fn):
    """Call fn(); return the ClientError's ``(code, message)``; an accepted call fails the check.

    The message is asserted on here, so it must be carried out of the except block rather than
    discarded: the CODE alone cannot distinguish "the topic is unknown" from "the CLUSTER is
    unknown" -- both are NotFoundException -- and this check would then pass for the wrong reason.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call was accepted; a ClientError refusal was expected")


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


def _active_cluster(ctx, msk, name_prefix, num_brokers=2):
    """Provision a PROVISIONED cluster and wait for ACTIVE (slow, but always runs)."""
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=num_brokers, name_prefix=name_prefix)
    _wait_cluster_active(msk, arn)
    return arn


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTopic for a TopicName that never existed -> NotFoundException.

    The control plane maps the miss onto its modelled NotFoundException ("The requested resource
    doesn't exist."), not the broker's UnknownTopicOrPartitionException nor an idempotent success.
    """
    msk = ctx.client("kafka")
    cluster_arn = _active_cluster(ctx, msk, "topic-delnf-cluster-", num_brokers=2)
    bogus_topic = ctx.unique_name("sim2real-behav-never-existed-")

    code, message = _err_pair(lambda: msk.delete_topic(ClusterArn=cluster_arn, TopicName=bogus_topic))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r} ({message!r})"
    assert message == "The requested resource doesn\u2019t exist.", f"DeleteTopic message: {message!r}"
    # The message cannot carry any part of the verdict: measured on real MSK it is the generic
    # "The requested resource doesn't exist." -- it names neither the topic nor the cluster, so it
    # is indistinguishable from the answer to a bad ClusterArn. Pin the miss to the TOPIC with a
    # control instead. ListTopics on the SAME ClusterArn succeeding proves both that the cluster
    # resolves and that the topic API is live on it (NotFoundException is not even among
    # ListTopics' modelled errors), and the bogus name must be absent from what it returns -- so
    # the rejected delete neither found nor created anything.
    topics = msk.list_topics(ClusterArn=cluster_arn).get("Topics", [])
    assert all(t.get("TopicName") != bogus_topic for t in topics), (
        f"{bogus_topic} must not exist after a rejected DeleteTopic, got {topics}"
    )

    # Positive control: DeleteTopic on THIS cluster genuinely works against a topic that really
    # exists, so the NotFoundException above is pinned to the bogus name rather than to a topic
    # API that rejects every delete (which would make "rejects an unknown topic" indistinguishable
    # from "rejects every topic").
    real_topic = ctx.unique_name("sim2real-behav-real-")
    msk.create_topic(ClusterArn=cluster_arn, TopicName=real_topic, PartitionCount=1, ReplicationFactor=2)
    _wait_topic_active(msk, cluster_arn, real_topic)
    msk.delete_topic(ClusterArn=cluster_arn, TopicName=real_topic)
    # DeleteTopic's own removal is eventually consistent -- an immediate DescribeTopic can still
    # report the topic for a short window, so this is a bounded poll, not a single read.
    _poll_until(
        lambda: _gone(lambda: msk.describe_topic(ClusterArn=cluster_arn, TopicName=real_topic)),
        lambda gone: gone,
        timeout_s=180,
        interval_s=5,
        description=f"real topic {real_topic} to disappear after DeleteTopic",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
