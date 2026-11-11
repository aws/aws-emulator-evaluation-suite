"""update-topic-controller-moved-exception."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "update-topic-controller-moved-exception"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTopic sets retention.ms to 3600000 on a live cluster, RebootBroker completes for every broker
    in turn, and afterwards UpdateTopic still sets retention.ms to 7200000 as read back by DescribeTopic."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_provisioned_cluster(ctx)
    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=1)
    ctx.on_cleanup(lambda: kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name))
    # UpdateTopic needs an ACTIVE topic; the topic APIs "reflect data that updates approximately
    # every minute" (https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-topics.html).
    _poll_until(
        lambda: _topic_status(kafka, cluster_arn, topic_name),
        lambda status: status == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )

    # Real, observable outcome #1: UpdateTopic against a healthy cluster actually persists a
    # new topic-level config end-to-end (not just a 200 response).
    kafka.update_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        Configs=_b64_configs({"retention.ms": "3600000"}),
    )
    _poll_until(
        lambda: _topic_configs(kafka, cluster_arn, topic_name).get("retention.ms"),
        lambda value: value == "3600000",
        timeout_s=300,
        interval_s=10,
    )

    # Drive the only real-world trigger for controller migration: reboot every broker. This
    # is a genuine, observable state transition (ACTIVE -> REBOOTING_BROKER -> ACTIVE), not a
    # bare sleep -- we poll for it explicitly both leaving and returning to ACTIVE.
    nodes = kafka.list_nodes(ClusterArn=cluster_arn)["NodeInfoList"]
    # ListNodes reports BrokerId as a number (2.0); RebootBroker takes broker ids as strings.
    broker_ids = [str(int(n["BrokerNodeInfo"]["BrokerId"])) for n in nodes if "BrokerNodeInfo" in n]
    assert broker_ids, "expected at least one broker node on the cluster"
    # RebootBroker takes one broker id per call ("Too many brokers specified. Specify only one
    # broker id"), so the brokers are rebooted one after another. The cluster
    # can still read ACTIVE right after RebootBroker returns, so each reboot is tracked through its
    # own cluster operation until it completes.
    for broker_id in broker_ids:
        op_arn = kafka.reboot_broker(ClusterArn=cluster_arn, BrokerIds=[broker_id])["ClusterOperationArn"]
        reboot_state = _poll_until(
            lambda op_arn=op_arn: kafka.describe_cluster_operation_v2(
                ClusterOperationArn=op_arn
            )["ClusterOperationInfo"]["OperationState"],
            # A RebootBroker operation ends REBOOT_COMPLETE.
            lambda state: state in ("REBOOT_COMPLETE", "UPDATE_COMPLETE", "REBOOT_FAILED", "UPDATE_FAILED"),
            timeout_s=1200,
            interval_s=15,
        )
        assert reboot_state in ("REBOOT_COMPLETE", "UPDATE_COMPLETE"), (
            f"the reboot of broker {broker_id} ended {reboot_state}, so no controller migration was forced"
        )
        _poll_until(
            lambda: kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"],
            lambda state: state == "ACTIVE",
            timeout_s=600,
            interval_s=15,
        )

    # Real, observable outcome #2: after the full broker-restart storm (during which a
    # controller migration is guaranteed to have happened at least once), UpdateTopic against
    # the now-healthy cluster still actually persists a config change end-to-end.
    kafka.update_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        Configs=_b64_configs({"retention.ms": "7200000"}),
    )
    final_configs = _poll_until(
        lambda: _topic_configs(kafka, cluster_arn, topic_name).get("retention.ms"),
        lambda value: value == "7200000",
        timeout_s=300,
        interval_s=10,
    )
    assert final_configs == "7200000", (
        f"expected retention.ms == '7200000' via an independent DescribeTopic read after the "
        f"broker-restart storm, got {final_configs!r}"
    )


def _b64_configs(configs: dict[str, str]) -> str:
    """UpdateTopic/DescribeTopic `Configs` is a STRING holding BASE64 of a JSON object of string
    values ("Topic configurations encoded as a Base64 string" in the kafka model). Real AWS accepts
    {"retention.ms": "3600000"} and rejects Kafka property text ("retention.ms=3600000") with
    "The provided configurations are invalid"; DescribeTopic returns the same base64 JSON."""
    return base64.b64encode(json.dumps(configs).encode("utf-8")).decode("ascii")


def _topic_status(kafka, cluster_arn, topic_name):
    try:
        return kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Status")
    except kafka.exceptions.NotFoundException:
        return None


def _topic_configs(kafka, cluster_arn, topic_name) -> dict[str, str]:
    """DescribeTopic's base64 `Configs` decoded into a dict; {} while the topic API lags."""
    try:
        raw = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Configs") or ""
    except kafka.exceptions.NotFoundException:
        return {}
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    return json.loads(base64.b64decode(raw).decode("utf-8")) if raw else {}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_provisioned_cluster(ctx):
    kafka = ctx.client("kafka")
    net = ctx.network()
    subnet_ids, sg_id = net.subnet_ids[:2], net.security_group_id
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    cluster_arn = kafka.create_cluster(
        ClusterName=ctx.unique_name("sim2real-behav-kafka-"),
        KafkaVersion="3.9.x",
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
        Tags={"sim2real:managed": "true"},
    )["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_arn))
    # A two-broker kafka.t3.small cluster can stay in CREATING past 1800 s.
    _wait_cluster_active(ctx, cluster_arn, timeout_s=3000.0)
    return cluster_arn


def _delete_cluster(ctx, cluster_arn):
    """DeleteCluster is refused while the cluster is CREATING ("You can't delete cluster in
    CREATING state"), so a cluster the run left creating is let settle
    first (bounded: if it does not, the delete reports the refusal)."""
    try:
        _wait_cluster_active(ctx, cluster_arn, timeout_s=1500.0)
    except AssertionError:
        pass
    ctx.client("kafka").delete_cluster(ClusterArn=cluster_arn)


def _wait_cluster_active(ctx, cluster_arn, timeout_s=1800.0, interval_s=30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
