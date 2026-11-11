"""topic-replication-factor-exceeds-broker-count-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-replication-factor-exceeds-broker-count-rejected"
GROUP = "state-machine"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopic rejects a ReplicationFactor greater than the cluster's broker
    count, while a topic with a valid replication factor succeeds on the very same
    cluster (positive control), and the over-replicated topic is never created."""
    kafka_version = _pick_active_kafka_version(ctx)
    cluster_arn = _create_basic_cluster(ctx, kafka_version)  # exactly 2 brokers
    kafka = ctx.client("kafka")

    # Positive control: replication factor within the broker count succeeds.
    good_topic = ctx.unique_name("sim2real-behav-topic-good-")
    kafka.create_topic(
        ClusterArn=cluster_arn, TopicName=good_topic, PartitionCount=1, ReplicationFactor=2
    )
    ctx.on_cleanup(lambda: _delete_topic_settled(kafka, cluster_arn, good_topic))
    good_info = _poll_topic_visible(ctx, cluster_arn, good_topic)
    assert good_info.get("ReplicationFactor") == 2, (
        f"expected the accepted topic to persist ReplicationFactor=2, got {good_info!r}"
    )

    # Negative: replication factor far exceeding the 2-broker cluster is rejected.
    bad_topic = ctx.unique_name("sim2real-behav-topic-bad-")
    code = _error_code(
        lambda: kafka.create_topic(
            ClusterArn=cluster_arn, TopicName=bad_topic, PartitionCount=1, ReplicationFactor=10
        )
    )
    expected = ("BadRequestException", "Replication factor: 10 larger than available brokers: 2.")
    assert code == expected, (
        f"ReplicationFactor exceeding broker count: expected {expected!r}, got {code!r}"
    )

    # Effect must be absent: the over-replicated topic was never created, checked two ways.
    topic_names = {t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn).get("Topics", [])}
    assert bad_topic not in topic_names, (
        "a topic was created despite CreateTopic rejecting its over-large ReplicationFactor"
    )
    describe_code = _error_code(lambda: kafka.describe_topic(ClusterArn=cluster_arn, TopicName=bad_topic))
    assert describe_code == _NOT_FOUND, (
        f"expected DescribeTopic to report {_NOT_FOUND!r} for the rejected topic, got {describe_code!r}"
    )


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


# MSK's message for a topic or cluster that resolves to nothing (U+2019 apostrophe).
_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


def _delete_topic_settled(kafka, cluster_arn: str, topic_name: str, timeout_s: float = 300.0) -> None:
    """Teardown: wait out CREATING (MSK refuses DeleteTopic then), then delete; a missing topic is fine."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Status")
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if status != "CREATING" or time.monotonic() > deadline:
            break
        time.sleep(5)
    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_topic_visible(ctx, cluster_arn: str, topic_name: str, timeout_s: float = 240.0, interval_s: float = 10.0) -> dict:
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except Exception:  # noqa: BLE001 - NotFoundException while it propagates
            time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never became visible within {timeout_s}s")


def _default_client_subnets(ctx, count: int = 2) -> list[str]:
    """`count` subnets in distinct AZs of the run's network (ctx.network())."""
    net = ctx.network()
    zones = net.availability_zones
    if len(zones) < count:
        raise AssertionError(f"the run's network has subnets in {len(zones)} AZs, need {count} for MSK brokers")
    return [net.subnets[az] for az in zones][:count]


def _poll_cluster_state(
    ctx, cluster_arn: str, desired: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info["State"]
        if last in desired:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state: {info.get('StateInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {desired} within {timeout_s}s (last state={last})")


def _create_basic_cluster(ctx, kafka_version: str, **extra: Any) -> str:
    kafka = ctx.client("kafka")
    subnets = _default_client_subnets(ctx, 2)
    name = ctx.unique_name("sim2real-behav-")
    kwargs: dict[str, Any] = dict(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=len(subnets),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnets,
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
        },
        Tags={"sim2real:managed": "true"},
    )
    kwargs.update(extra)
    resp = kafka.create_cluster(**kwargs)
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ctx, kafka, arn))
    _poll_cluster_state(ctx, arn, {"ACTIVE"})
    return arn


def _pick_active_kafka_version(ctx) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


# One deadline shared by all of the check's teardowns, inside the suite's 1800 s cleanup budget.
_TEARDOWN_S = 1740.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _delete_cluster_when_settled(ctx, msk, arn, interval_s=2.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING (BadRequestException), so wait for
    ACTIVE or FAILED first; then poll until DescribeClusterV2 answers NotFoundException, all to the
    shared teardown deadline."""
    deadline = _deadline(ctx)
    state = None
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} at the teardown deadline")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
