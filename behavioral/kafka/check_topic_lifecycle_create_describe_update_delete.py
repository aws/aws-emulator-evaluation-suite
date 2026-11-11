"""topic-lifecycle-create-describe-update-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-lifecycle-create-describe-update-delete"
GROUP = "state-machine"
SERVICES = ["kafka"]

# Named in the failure detail when a state machine the target accepted never converges, so the
# failure reads as a control-plane convergence failure rather than a connection error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTopic yields an ACTIVE topic with 1 partition and replication factor 2 that ListTopics lists,
    UpdateTopic raises it to 2 partitions, and after DeleteTopic it leaves DescribeTopic and ListTopics and
    UpdateTopic fails with NotFoundException and its exact message."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_active_cluster(ctx, num_brokers=2)
    topic_name = ctx.unique_name("sim2real-topic-")

    kafka.create_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        PartitionCount=1,
        ReplicationFactor=2,
    )
    ctx.on_cleanup(lambda: _delete_topic_ignore_missing(ctx, cluster_arn, topic_name))

    info = _wait_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180)
    assert info["Status"] == "ACTIVE", f"expected Status ACTIVE after create, got {info['Status']}"
    assert info["PartitionCount"] == 1, f"expected PartitionCount 1 after create, got {info['PartitionCount']}"
    assert info["ReplicationFactor"] == 2, f"expected ReplicationFactor 2 after create, got {info['ReplicationFactor']}"

    parts = kafka.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=topic_name)
    assert len(parts["Partitions"]) == 1, f"expected 1 partition after create, got {len(parts['Partitions'])}"

    names = [t["TopicName"] for t in _list_all_topics(ctx, cluster_arn)]
    assert topic_name in names, f"{topic_name} missing from ListTopics after create"

    kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=2)
    updated = _wait_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180)
    assert updated["PartitionCount"] == 2, f"expected PartitionCount 2 after update, got {updated['PartitionCount']}"

    parts_after = kafka.describe_topic_partitions(ClusterArn=cluster_arn, TopicName=topic_name)
    assert len(parts_after["Partitions"]) == 2, f"expected 2 partitions after update, got {len(parts_after['Partitions'])}"

    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    deadline = time.monotonic() + 180
    removed = False
    while time.monotonic() < deadline:
        if _is_gone(lambda: kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)):
            removed = True
            break
        time.sleep(3)
    assert removed, "DescribeTopic did not 404 after DeleteTopic completed"

    names_after = [t["TopicName"] for t in _list_all_topics(ctx, cluster_arn)]
    assert topic_name not in names_after, f"{topic_name} still in ListTopics after DeleteTopic"

    dead = _error(
        lambda: kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=3)
    )
    assert dead == ("NotFoundException", "The requested resource doesn\u2019t exist."), (
        f"expected NotFoundException mutating a deleted topic, got {dead}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _is_gone(fn):
    """Call fn(); True when it answers NotFoundException, False when it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return True
        raise
    return False


def _pick_subnets_and_sg(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    seen_az, chosen = set(), []
    for s in subnets:
        if s["AvailabilityZone"] not in seen_az:
            seen_az.add(s["AvailabilityZone"])
            chosen.append(s["SubnetId"])
        if len(chosen) >= count:
            break
    if len(chosen) < count:
        raise AssertionError("not enough distinct-AZ subnets in the shared network to create an MSK test cluster")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return chosen, sg_id


def _wait_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if last_state in target_states:
            return last_state
        time.sleep(interval_s)
    raise _never_ready(
        f"cluster did not reach {target_states} within {timeout_s}s (last state={last_state})",
    )


def _create_active_cluster(ctx, num_brokers=2, security_group_ids=None, instance_type="kafka.t3.small", timeout_s=1800):
    kafka = ctx.client("kafka")
    subnets, default_sg = _pick_subnets_and_sg(ctx, count=num_brokers)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    def _version_key(v):
        # ZooKeeper versions before KRaft ones, then newest first; a "x" patch level sorts high.
        parts = v["Version"].split(".")
        numbers = tuple(int(p) if p.isdigit() else 99 for p in parts[:3])
        return ("kraft" not in parts, numbers)

    # Try the newest available Kafka versions first, falling back to older ones: MSK sometimes
    # reserves the single newest version returned by ListKafkaVersions for a different broker
    # category (e.g. Express-only) and rejects "Standard" instance types like kafka.t3.small
    # with a BadRequestException ("Standard instance types are not supported for Kafka version
    # ..."), while the next-newest version supports them fine. Probe candidates newest-first via
    # the real CreateCluster call instead of assuming the newest entry is always usable.
    versions.sort(key=_version_key, reverse=True)
    # Standard brokers reject every DEPRECATED Kafka version.
    versions = [v for v in versions if v.get("Status") == "ACTIVE"]
    sg_ids = security_group_ids if security_group_ids is not None else ([default_sg] if default_sg else [])
    name = ctx.unique_name("sim2real-msk-")
    cluster_arn = None
    last_bad_request = None
    for v in versions[:6]:
        try:
            resp = kafka.create_cluster(
                ClusterName=name,
                KafkaVersion=v["Version"],
                NumberOfBrokerNodes=num_brokers,
                BrokerNodeGroupInfo={
                    "InstanceType": instance_type,
                    "ClientSubnets": subnets,
                    "SecurityGroups": sg_ids,
                    "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
                },
                Tags={"sim2real:managed": "true"},
            )
            cluster_arn = resp["ClusterArn"]
            break
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "BadRequestException" and "not supported for Kafka version" in msg:
                last_bad_request = e
                continue
            raise
    if cluster_arn is None:
        raise AssertionError(
            f"no available Kafka version supports instance type {instance_type} via CreateCluster: {last_bad_request}"
        )

    def _cleanup():
        try:
            _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
        except AssertionError:
            pass
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if _is_gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
                return
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still exists {timeout_s}s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


def _wait_topic_status(ctx, cluster_arn, topic_name, target_statuses, timeout_s=180, interval_s=3):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        if last.get("Status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached {target_statuses}, last={last}")


def _list_all_topics(ctx, cluster_arn):
    kafka = ctx.client("kafka")
    topics, token = [], None
    while True:
        kwargs = {"ClusterArn": cluster_arn}
        if token:
            kwargs["NextToken"] = token
        resp = kafka.list_topics(**kwargs)
        topics.extend(resp.get("Topics", []))
        token = resp.get("NextToken")
        if not token:
            break
    return topics


def _delete_topic_ignore_missing(ctx, cluster_arn, topic_name):
    kafka = ctx.client("kafka")
    # DeleteTopic refuses a topic that is still CREATING, so retry for a while.
    deadline = time.monotonic() + 300
    while True:
        try:
            kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            return
        except ClientError as e:
            if "CREATING state" in e.response["Error"].get("Message", "") and time.monotonic() < deadline:
                time.sleep(10)
                continue
            if e.response["Error"]["Code"] not in ("NotFoundException", "UnknownTopicOrPartitionException"):
                raise
            return


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
