"""e2e-replicator-cross-cluster-topic-sync-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-replicator-cross-cluster-topic-sync-teardown"
GROUP = "e2e"
SERVICES = ["kafka"]

#: MSK control-plane refusals for a topic/replicator the API does not hold (measured on real
#: AWS; the apostrophe is U+2019, not ASCII).
_TOPIC_NOT_FOUND = ("NotFoundException", "The requested resource doesn’t exist.")
_REPLICATOR_NOT_FOUND = (
    "NotFoundException",
    "Invalid parameter replicatorArn: The requested resource doesn’t exist.",
)

#: MSK Replicator refuses a cluster with fewer than 3 brokers: with 2 it is accepted and then
#: settles FAILED with InvalidInput.InvalidKafkaCluster. NumberOfBrokerNodes must be a multiple of
#: the client-subnet count, so 3 subnets x 1 broker is the cheapest combination that clears it.
_MIN_BROKERS = 3


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """A source topic created after a Replicator is RUNNING appears in the target cluster's
    ListTopics, and DeleteTopic and DeleteReplicator each end in independently observed absence."""
    kafka = ctx.client("kafka")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    # Role first: CreateReplicator validates it synchronously, and the ~20-30 min of cluster
    # provisioning that follows is far more IAM propagation time than kafka.amazonaws.com needs --
    # so no separate sleep is needed for that beat.
    role_arn, role_name, policy_arn = _create_replicator_role(ctx, iam, sts)

    subnet_ids, sg_id = _discover_network(ctx, num_subnets=_MIN_BROKERS)

    # Registered before the clusters, so it runs after both DeleteCluster teardowns have started.
    cluster_arns = []
    ctx.on_cleanup(lambda: _wait_clusters_gone(kafka, cluster_arns))
    source_arn, kafka_version = _create_cluster_with_version_fallback(ctx, kafka, subnet_ids, sg_id, "source")
    cluster_arns.append(source_arn)
    target_arn = _create_cluster(ctx, kafka, subnet_ids, sg_id, kafka_version, "target")
    cluster_arns.append(target_arn)
    _wait_cluster_active(kafka, source_arn)
    _wait_cluster_active(kafka, target_arn)

    topic_name = ctx.unique_name("sim2real-repl-topic-")
    replicator_name = ctx.unique_name("sim2real-replicator-")
    create_repl = _create_replicator_with_retry(
        ctx, kafka, replicator_name, role_arn, source_arn, target_arn, subnet_ids, sg_id, topic_name
    )
    replicator_arn = create_repl["ReplicatorArn"]
    ctx.on_cleanup(
        lambda: _teardown(lambda: kafka.delete_replicator(ReplicatorArn=replicator_arn), kafka.exceptions.NotFoundException)
    )
    info = _wait_replicator_state(kafka, replicator_arn, {"RUNNING"}, {"FAILED"})
    assert info["ReplicatorState"] == "RUNNING", (
        f"replicator {replicator_arn} did not reach RUNNING: {info.get('StateInfo')}"
    )

    kafka.create_topic(ClusterArn=source_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=2)
    ctx.on_cleanup(lambda: _delete_topic_teardown(kafka, source_arn, topic_name))

    def _target_has_topic():
        topics = kafka.list_topics(ClusterArn=target_arn).get("Topics", [])
        return [t["TopicName"] for t in topics if topic_name in t["TopicName"]]

    matches = _poll_until(_target_has_topic, lambda m: len(m) > 0, timeout_s=900.0, interval_s=15.0)
    assert matches, f"source topic {topic_name!r} never appeared on the target cluster's ListTopics"

    # An independent read confirms each delete's effect.
    # DeleteTopic refuses a topic MSK still reports CREATING, so wait for the source topic's ACTIVE.
    _poll_until(
        lambda: _topic_status(kafka, source_arn, topic_name),
        lambda status: status == "ACTIVE",
        timeout_s=300.0,
    )
    kafka.delete_topic(ClusterArn=source_arn, TopicName=topic_name)
    topic_gone = _poll_until(
        lambda: _outcome(lambda: kafka.describe_topic(ClusterArn=source_arn, TopicName=topic_name)),
        lambda result: result == _TOPIC_NOT_FOUND,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert topic_gone == _TOPIC_NOT_FOUND, (
        f"deleted topic {topic_name!r} never resolved to {_TOPIC_NOT_FOUND!r} on an independent read, "
        f"got {topic_gone!r}"
    )

    kafka.delete_replicator(ReplicatorArn=replicator_arn)
    replicator_gone = _poll_until(
        lambda: _outcome(lambda: kafka.describe_replicator(ReplicatorArn=replicator_arn)),
        lambda result: result == _REPLICATOR_NOT_FOUND,
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert replicator_gone == _REPLICATOR_NOT_FOUND, (
        f"deleted replicator {replicator_arn!r} never resolved to {_REPLICATOR_NOT_FOUND!r} on an "
        f"independent read, got {replicator_gone!r}"
    )


def _teardown(fn, not_found_exc):
    """Run fn(); only the resource's own not-found exception means it is already gone."""
    try:
        fn()
    except not_found_exc:
        pass


def _wait_clusters_gone(kafka, cluster_arns, timeout_s=1500.0, interval_s=30.0):
    """Wait until DescribeClusterV2 returns NotFoundException for every cluster; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    pending = list(cluster_arns)
    while pending:
        for arn in list(pending):
            try:
                kafka.describe_cluster_v2(ClusterArn=arn)
            except kafka.exceptions.NotFoundException:
                pending.remove(arn)
        if pending and time.monotonic() >= deadline:
            raise AssertionError(f"clusters {pending} still exist {timeout_s:.0f}s after DeleteCluster")
        if pending:
            time.sleep(interval_s)


def _outcome(fn):
    """("ok", None) while fn() succeeds (the resource is still there), else its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "ok", None


def _topic_status(kafka, cluster_arn, topic_name):
    """The topic's Status, or None while the topic APIs, which lag about a minute, do not list it yet."""
    try:
        return kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Status")
    except kafka.exceptions.NotFoundException:
        return None


def _delete_topic_teardown(kafka, cluster_arn, topic_name, timeout_s=300.0):
    """DeleteTopic, retried every 2 s while MSK refuses a topic still CREATING; NotFoundException means gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "NotFoundException":
                return
            if err.get("Message") != "You can't delete a topic in CREATING state." or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _discover_network(ctx, num_subnets: int):
    """`num_subnets` subnets in distinct availability zones of the run's shared network
    (ctx.network()), plus the VPC's default security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= num_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {num_subnets}"
    )
    return [net.subnets[az] for az in zones][:num_subnets], net.security_group_id


def _active_kafka_versions(kafka) -> list[str]:
    resp = kafka.list_kafka_versions()
    versions = [v["Version"] for v in resp.get("KafkaVersions", []) if v.get("Status") == "ACTIVE"]
    if not versions:
        versions = [v["Version"] for v in resp.get("KafkaVersions", [])]
    if not versions:
        raise AssertionError("ListKafkaVersions returned no versions")
    return sorted(versions, reverse=True)


def _create_cluster_with_version_fallback(ctx, kafka, subnet_ids, sg_id, role):
    """Create on the newest ACTIVE Kafka version CreateCluster accepts for kafka.m5.large.
    ListKafkaVersions has no Standard/Express field, and Express-only *.kraft releases are
    rejected with BadRequestException."""
    candidates = _active_kafka_versions(kafka)
    last_exc = None
    for version in candidates:
        try:
            return _create_cluster(ctx, kafka, subnet_ids, sg_id, version, role), version
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            last_exc = exc
    raise AssertionError(
        f"no ACTIVE Kafka version among {candidates!r} was accepted for a Standard broker: {last_exc}"
    )


def _create_cluster(ctx, kafka, subnet_ids, sg_id, kafka_version, role):
    name = ctx.unique_name(f"sim2real-msk-{role}-")
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=_MIN_BROKERS,
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
        },
        # MSK Replicator reaches both clusters over IAM access control (port 9098) only, so a
        # cluster without SASL/IAM can never host one.
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(
        lambda: _teardown(lambda: kafka.delete_cluster(ClusterArn=cluster_arn), kafka.exceptions.NotFoundException)
    )
    return cluster_arn


def _wait_cluster_active(kafka, cluster_arn, timeout_s=2700.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if state == "ACTIVE":
            return
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s, last state {state}")


def _create_replicator_role(ctx, iam, sts):
    account_id = sts.get_caller_identity()["Account"]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kafka.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-msk-replicator-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"
    # Registered before any cluster/replicator teardown so LIFO runs it LAST: the replicator holds
    # this role while it exists, so detaching/deleting it earlier would fail (or, worse, race).
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=role_name), iam.exceptions.NoSuchEntityException))
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), iam.exceptions.NoSuchEntityException
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn, role_name, policy_arn


def _create_replicator_with_retry(ctx, kafka, name, role_arn, source_arn, target_arn, subnet_ids, sg_id, topic_name):
    replication_info = {
        "SourceKafkaClusterArn": source_arn,
        "TargetKafkaClusterArn": target_arn,
        "TargetCompressionType": "NONE",
        "TopicReplication": {"TopicsToReplicate": [topic_name]},
        "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
    }
    kafka_clusters = [
        {
            "AmazonMskCluster": {"MskClusterArn": arn},
            # The same security group as the clusters: its default self-referencing rule is what
            # lets the replicator's ENIs reach the brokers on 9098, and a bare SubnetIds VpcConfig
            # leaves that to whatever MSK defaults to instead.
            "VpcConfig": {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
        }
        for arn in (source_arn, target_arn)
    ]
    # IAM propagation is already covered by the cluster-creation wait that precedes this call; a
    # short deadline-bound retry here only guards a transient CreateReplicator error.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            return kafka.create_replicator(
                ReplicatorName=name,
                ServiceExecutionRoleArn=role_arn,
                KafkaClusters=kafka_clusters,
                ReplicationInfoList=[replication_info],
                Tags={"sim2real:managed": "true"},
            )
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _wait_replicator_state(kafka, replicator_arn, success_states, failure_states, timeout_s=2700.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        state = info["ReplicatorState"]
        if state in success_states or state in failure_states:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"replicator {replicator_arn} did not settle within {timeout_s}s, last state {state!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
