"""update-replication-info-server-enforced-propagation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-replication-info-server-enforced-propagation"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A successful UpdateReplicationInfo change to the topic-replication filter is applied by the
    server and shows in DescribeReplicator's ReplicationInfoList once the replicator is RUNNING
    again; the update lands asynchronously (UPDATING first), so the check polls for it.
    """
    kafka = ctx.client("kafka")
    net = ctx.network()
    subnet_ids, sg_id = net.subnet_ids[:3], net.security_group_id
    # Created before the clusters, so IAM has propagated the role by the time MSK assumes it.
    role_arn = _create_replicator_role(ctx)
    source_arn = _create_cluster(ctx, subnet_ids, sg_id, "sim2real-replsrc2-")
    target_arn = _create_cluster(ctx, subnet_ids, sg_id, "sim2real-repldst2-")

    replicator_arn, current_version = _create_replicator(ctx, source_arn, target_arn, subnet_ids, sg_id, role_arn)

    before = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    before_topics = before["ReplicationInfoList"][0]["TopicReplication"]["TopicsToReplicate"]
    assert "sim2real-new-pattern.*" not in before_topics

    resp = kafka.update_replication_info(
        ReplicatorArn=replicator_arn,
        CurrentVersion=current_version,
        SourceKafkaClusterArn=source_arn,
        TargetKafkaClusterArn=target_arn,
        TopicReplication={
            "TopicsToReplicate": ["sim2real.*", "sim2real-new-pattern.*"],
            "TopicsToExclude": [],
            "CopyTopicConfigurations": True,
            "CopyAccessControlListsForTopics": False,
            "DetectAndCopyNewTopics": True,
        },
    )
    assert resp["ReplicatorState"] in {"RUNNING", "UPDATING"}

    # The update lands asynchronously: poll until the replicator is RUNNING with the new filter.
    deadline = time.monotonic() + 900.0
    final = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    while time.monotonic() < deadline:
        final = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        if final["ReplicatorState"] == "FAILED":
            raise AssertionError(f"replicator entered FAILED after UpdateReplicationInfo: {final}")
        if (final["ReplicatorState"] == "RUNNING"
                and "sim2real-new-pattern.*" in final["ReplicationInfoList"][0]["TopicReplication"]["TopicsToReplicate"]):
            break
        time.sleep(2)
    final_topics = final["ReplicationInfoList"][0]["TopicReplication"]["TopicsToReplicate"]
    assert final["ReplicatorState"] == "RUNNING", f"replicator did not return to RUNNING: {final['ReplicatorState']}"
    assert "sim2real-new-pattern.*" in final_topics, (
        f"the new topic pattern never reached DescribeReplicator within 900s, got {final_topics}"
    )


# ===== helpers =====

def _pick_kafka_version(kafka) -> str:
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _create_cluster(ctx, subnet_ids, sg_id, prefix: str) -> str:
    kafka = ctx.client("kafka")
    name = ctx.unique_name(prefix)
    version = _pick_kafka_version(kafka)
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
        },
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
    )
    arn = resp["ClusterArn"]
    if not _CLUSTERS:
        # Registered before the first cluster's delete, so it runs after every DeleteCluster was
        # sent and the clusters delete in parallel inside the teardown budget.
        ctx.on_cleanup(lambda: _wait_clusters_deleted(ctx, _CLUSTERS))
    _CLUSTERS.append(arn)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=3000)
    return arn


_CLUSTERS: list = []


def _delete_cluster(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _wait_clusters_deleted(ctx, arns, timeout_s=1200.0) -> None:
    deadline = time.monotonic() + timeout_s
    for arn in arns:
        _wait_cluster_deleted(ctx, arn, timeout_s=max(1.0, deadline - time.monotonic()))


def _wait_cluster_state(ctx, arn, target_states, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_cluster_deleted(ctx, arn, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("cluster did not delete within timeout")


def _create_replicator_role(ctx) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-msk-replicator-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "kafka.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account}},
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return f"arn:aws:iam::{account}:role/{role_name}"


def _create_replicator(ctx, source_arn, target_arn, subnet_ids, sg_id, role_arn):
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-replicator2-")
    resp = kafka.create_replicator(
        ReplicatorName=name,
        ServiceExecutionRoleArn=role_arn,
        KafkaClusters=[
            {
                "AmazonMskCluster": {"MskClusterArn": source_arn},
                "VpcConfig": {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
            },
            {
                "AmazonMskCluster": {"MskClusterArn": target_arn},
                "VpcConfig": {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
            },
        ],
        ReplicationInfoList=[{
            "SourceKafkaClusterArn": source_arn,
            "TargetKafkaClusterArn": target_arn,
            # REQUIRED by the CreateReplicator model (botocore ReplicationInfo.required lists
            # TargetCompressionType, TopicReplication, ConsumerGroupReplication). Omitting it
            # fails client-side with `Missing required parameter in ReplicationInfoList[0]:
            # "TargetCompressionType"`.
            "TargetCompressionType": "NONE",
            # No exclude lists: CreateReplicator answers "Too many or too few topics specified"
            # for one that also sends empty exclude lists with this topic-name configuration.
            "TopicReplication": {
                "TopicsToReplicate": ["sim2real.*"],
                "CopyTopicConfigurations": True,
                "CopyAccessControlListsForTopics": False,
                "DetectAndCopyNewTopics": True,
            },
            "ConsumerGroupReplication": {
                "ConsumerGroupsToReplicate": [".*"],
                "DetectAndCopyNewConsumerGroups": True,
                "SynchroniseConsumerGroupOffsets": False,
            },
        }],
    )
    arn = resp["ReplicatorArn"]
    ctx.on_cleanup(lambda: _delete_replicator(ctx, arn))
    info = _wait_replicator_state(ctx, arn, {"RUNNING"}, timeout_s=1800)
    return arn, info["CurrentVersion"]


def _delete_replicator(ctx, arn: str, timeout_s: float = 600.0) -> None:
    """DeleteReplicator is refused while the replicator is CREATING or UPDATING ("You can't delete
    a replicator in UPDATING state", observed on real AWS), so wait for it to settle first; then
    wait until it is gone, because a cluster a replicator still uses cannot be deleted."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_replicator(ReplicatorArn=arn)["ReplicatorState"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state not in ("CREATING", "UPDATING"):
            break
        time.sleep(20.0)
    if state != "DELETING":
        kafka.delete_replicator(ReplicatorArn=arn)
    while time.monotonic() < deadline:
        try:
            kafka.describe_replicator(ReplicatorArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(20.0)
    raise AssertionError(f"replicator {arn} still present {timeout_s}s into its teardown")


def _wait_replicator_state(ctx, arn, target_states, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    info = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=arn)
        last = info["ReplicatorState"]
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"replicator entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"replicator did not reach {target_states} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
