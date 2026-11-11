"""topic-retention-ms-numeric-precision-preserved."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "topic-retention-ms-numeric-precision-preserved"
GROUP = "state-machine"
SERVICES = ["kafka"]

_RETENTION_MS = "9223372036854775807"  # int64 max: any float64 round-trip would drift this


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large retention.ms value passed to CreateTopic comes back from DescribeTopic as the exact same
    number, without truncation or float drift, and DescribeTopicPartitions shows the topic's single
    partition."""
    kafka_version = _pick_active_kafka_version(ctx, minimum=(3, 6, 0))
    cluster_arn = _create_basic_cluster(ctx, kafka_version)
    kafka = ctx.client("kafka")

    topic_name = ctx.unique_name("sim2real-behav-topic-")
    configs_text = json.dumps({"retention.ms": _RETENTION_MS})
    kafka.create_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        PartitionCount=1,
        ReplicationFactor=2,
        Configs=_b64_configs(configs_text),
    )
    ctx.on_cleanup(lambda: _delete_topic(ctx, cluster_arn, topic_name))

    described = _poll_describe_topic(ctx, cluster_arn, topic_name)
    # DescribeTopic returns `Configs` base64-encoded too (same model doc), so decode before
    # parsing -- otherwise the assertion below reads the base64 text and never finds retention.ms.
    raw_configs = described["Configs"]
    if isinstance(raw_configs, (bytes, bytearray)):
        raw_configs = raw_configs.decode("utf-8")
    raw_configs = base64.b64decode(raw_configs).decode("utf-8")
    parsed = json.loads(raw_configs)
    assert "retention.ms" in parsed, f"retention.ms missing from returned Configs: {raw_configs!r}"
    assert parsed["retention.ms"] == _RETENTION_MS, (
        f"retention.ms round-tripped as {parsed['retention.ms']!r}, expected {_RETENTION_MS!r} "
        "(precision loss / truncation)"
    )

    # DescribeTopic already carries Configs while the topic is CREATING, when
    # DescribeTopicPartitions still answers NotFoundException; the topic is
    # ACTIVE when _poll_describe_topic returns, and the partitions are polled the same way.
    partitions = _poll(
        lambda: _describe_partitions_or_none(kafka, cluster_arn, topic_name), timeout_s=240.0
    )
    assert len(partitions["Partitions"]) == 1


def _b64_configs(text: str) -> str:
    # CreateTopic's `Configs` is a STRING in the kafka model ("Topic configurations encoded as a
    # Base64 string"), NOT a blob -- so boto3 does no transport encoding and the caller must
    # base64 it. What it encodes is a JSON object of string values: real AWS accepts
    # {"retention.ms": "3600000"} and rejects Kafka property text ("retention.ms=3600000") with
    # "The provided configurations are invalid", and DescribeTopic returns the topic's configs as
    # the same base64 JSON object.
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _poll_describe_topic(ctx, cluster_arn: str, topic_name: str, timeout_s: float = 240.0, interval_s: float = 10.0):
    # DescribeTopic documents ~1 minute of propagation lag after CreateTopic.
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except Exception as err:  # noqa: BLE001 - NotFoundException while it propagates
            last_err = err
            time.sleep(interval_s)
            continue
        if resp.get("Configs") and resp.get("Status") == "ACTIVE":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"DescribeTopic never surfaced Configs within {timeout_s}s (last_err={last_err})")


def _describe_partitions_or_none(kafka, cluster_arn: str, topic_name: str):
    try:
        return kafka.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=topic_name)
    except kafka.exceptions.NotFoundException:
        return None


def _poll(probe, timeout_s: float, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if got is not None or time.monotonic() >= deadline:
            assert got is not None, f"no answer within {timeout_s}s"
            return got
        time.sleep(interval_s)


def _delete_topic(ctx, cluster_arn: str, topic_name: str, timeout_s: float = 300.0) -> None:
    """DeleteTopic is refused while the topic is CREATING ("You can't delete a topic in CREATING
    state"), so it waits for the topic to settle first (bounded)."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Status")
        except kafka.exceptions.NotFoundException:
            status = None
        if status != "CREATING":
            break
        time.sleep(10.0)
    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except kafka.exceptions.NotFoundException:
        pass


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
    subnets = ctx.network().subnet_ids[:2]
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
        Tags={"sim2real": CHECK},
    )
    kwargs.update(extra)
    resp = kafka.create_cluster(**kwargs)
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    # A two-broker kafka.t3.small cluster can stay in CREATING past 1800 s.
    _poll_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=3000.0)
    return arn


def _delete_cluster(ctx, arn: str) -> None:
    """DeleteCluster is refused while the cluster is CREATING, so a cluster the run left creating
    is let settle first (bounded: if it does not, the delete reports the refusal)."""
    try:
        _poll_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=1500.0)
    except AssertionError:
        pass
    ctx.client("kafka").delete_cluster(ClusterArn=arn)


def _pick_active_kafka_version(ctx, minimum: tuple[int, int, int] | None = None) -> str:
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    kafka = ctx.client("kafka")
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
