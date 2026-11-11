"""concurrent-topic-partition-increase-race."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-topic-partition-increase-race"
GROUP = "concurrency"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateTopic calls raising the same topic from 1 to 3 partitions: exactly one
    succeeds, the other fails with BadRequestException, and the topic ends with 3 partitions."""
    kafka = ctx.client("kafka")
    subnet_ids = _pick_subnets_multi_az(ctx, count=3)
    cluster_arn = _create_msk_cluster(ctx, ctx.unique_name("sim2real-kafka-race-"), subnet_ids)

    topic_name = ctx.unique_name("sim2real-race-topic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=1)
    ctx.on_cleanup(lambda: _delete_topic_ignore(ctx, cluster_arn, topic_name))
    _wait_topic_active(ctx, cluster_arn, topic_name)

    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, str | None]] = {}

    def _call(label: str) -> None:
        try:
            barrier.wait(timeout=15)
        except threading.BrokenBarrierError:
            pass
        try:
            kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3)
            results[label] = ("ok", None)
        except ClientError as err:
            results[label] = ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_call, "A"), pool.submit(_call, "B")]
        for f in futures:
            f.result(timeout=60)

    outcomes = list(results.values())
    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly one racer to succeed, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one racer to be rejected, got {outcomes}"
    assert failures[0][1] == "BadRequestException", failures[0][1]

    _wait_topic_active(ctx, cluster_arn, topic_name)
    partitions = _list_all_partitions(ctx, cluster_arn, topic_name)
    assert len(partitions) == 3, f"expected the topic to end up with exactly 3 partitions, got {len(partitions)}"


def _pick_subnets_multi_az(ctx, count: int):
    """Distinct-AZ subnets to host the test cluster. Prefers the shared network but falls back to
    any VPC with enough AZ coverage, since a freshly provisioned account may have no shared network."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    seen_az: set[str] = set()
    chosen = []
    for s in subnets:
        if s["AvailabilityZone"] not in seen_az:
            seen_az.add(s["AvailabilityZone"])
            chosen.append(s["SubnetId"])
        if len(chosen) >= count:
            break
    if len(chosen) < count:
        raise AssertionError(
            f"fewer than {count} distinct-AZ subnets available in vpc {vpc_id}; "
            f"MSK Express brokers require {count} AZs"
        )
    return chosen


def _create_msk_cluster(ctx, name, subnet_ids, *, timeout_s=2400):
    """Create an MSK Express-broker cluster, which CreateCluster (v1) rejects outright --
    CreateClusterV2 is required. The newest
    Kafka version is sometimes reserved for a different broker category and rejects Express with
    its own BadRequestException, so probe candidates newest-first via the real call."""
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    def _key(v):
        # ZooKeeper versions before KRaft ones, then newest first; a "x" patch level sorts high.
        parts = v["Version"].split(".")
        numbers = tuple(int(p) if p.isdigit() else 99 for p in parts[:3])
        return ("kraft" not in parts, numbers)

    versions.sort(key=_key, reverse=True)
    # Express brokers reject every DEPRECATED Kafka version.
    versions = [v for v in versions if v.get("Status") == "ACTIVE"]
    cluster_arn = None
    last_bad_request = None
    for v in versions[:6]:
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=name,
                Provisioned={
                    "KafkaVersion": v["Version"],
                    "NumberOfBrokerNodes": len(subnet_ids),
                    "BrokerNodeGroupInfo": {
                        "InstanceType": "express.m7g.large",
                        "ClientSubnets": subnet_ids,
                    },
                },
                Tags={"sim2real:managed": "true"},
            )
            cluster_arn = resp["ClusterArn"]
            break
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if err.response["Error"]["Code"] == "BadRequestException" and "not supported for Kafka version" in msg:
                last_bad_request = err
                continue
            raise
    if cluster_arn is None:
        raise AssertionError(
            f"no available Kafka version supports Express instance types via CreateClusterV2: {last_bad_request}"
        )
    ctx.on_cleanup(lambda: _delete_cluster_ignore(ctx, cluster_arn))
    _wait_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=timeout_s, interval_s=20)
    return cluster_arn


def _delete_cluster_ignore(ctx, arn):
    try:
        ctx.client("kafka").delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_topic_ignore(ctx, cluster_arn, topic_name):
    try:
        ctx.client("kafka").delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_cluster_state(ctx, arn, ok_states, *, timeout_s, interval_s):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in ok_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {ok_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {ok_states} within {timeout_s}s (last state={last})")


def _wait_topic_active(ctx, cluster_arn, topic_name, *, timeout_s=180, interval_s=5):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        last = resp["Status"]
        if last == "ACTIVE":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached ACTIVE (last={last})")


def _list_all_partitions(ctx, cluster_arn, topic_name):
    kafka = ctx.client("kafka")
    partitions = []
    token = None
    while True:
        kwargs = {"ClusterArn": cluster_arn, "TopicName": topic_name}
        if token:
            kwargs["NextToken"] = token
        resp = kafka.describe_topic_partitions(**kwargs)
        partitions.extend(resp["Partitions"])
        token = resp.get("NextToken")
        if not token:
            return partitions


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
