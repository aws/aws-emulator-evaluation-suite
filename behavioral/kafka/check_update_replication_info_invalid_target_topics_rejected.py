"""update-replication-info-invalid-target-topics-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-replication-info-invalid-target-topics-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateReplicationInfo with a swapped source/target pair is rejected with the exact
    BadRequestException and leaves CurrentVersion and the stored entries unchanged, while an update
    with the correct pair succeeds and its change is visible on DescribeReplicator."""
    kafka = ctx.client("kafka")
    _, subnet_ids, sg_id = _network_subnets_sg(ctx)
    source_arn = _create_serverless_cluster(ctx, subnet_ids, sg_id)
    target_arn = _create_serverless_cluster(ctx, subnet_ids, sg_id)

    replicator_arn = _create_replicator(ctx, source_arn, target_arn, subnet_ids, sg_id)
    info = _wait_replicator_state(ctx, replicator_arn, "RUNNING")

    # Flipping DetectAndCopyNewTopics proves a real stored effect, not an echo;
    # TopicReplicationUpdate requires every field, so the topic pattern is resupplied unchanged.
    current_version = info["CurrentVersion"]
    good_update = kafka.update_replication_info(
        ReplicatorArn=replicator_arn,
        CurrentVersion=current_version,
        SourceKafkaClusterArn=source_arn,
        TargetKafkaClusterArn=target_arn,
        TopicReplication={
            "TopicsToReplicate": ["sim2real-behav-topic-.*"],
            "TopicsToExclude": [],
            "CopyTopicConfigurations": True,
            "CopyAccessControlListsForTopics": False,
            "DetectAndCopyNewTopics": True,
        },
    )
    assert good_update["ReplicatorState"] in ("UPDATING", "RUNNING"), (
        f"expected the accepted correct-pair update to report UPDATING or RUNNING, "
        f"got {good_update['ReplicatorState']!r}"
    )
    after_good = _wait_replicator_state(ctx, replicator_arn, "RUNNING")
    good_topic_repl = _topic_replication_of(after_good, source_arn, target_arn)
    assert good_topic_repl["DetectAndCopyNewTopics"] is True, (
        f"expected the accepted update's DetectAndCopyNewTopics=True to be applied and visible "
        f"on an independent DescribeReplicator, got {good_topic_repl!r}"
    )
    good_version = after_good["CurrentVersion"]

    code = _error_code(
        lambda: kafka.update_replication_info(
            ReplicatorArn=replicator_arn,
            CurrentVersion=good_version,
            SourceKafkaClusterArn=target_arn,
            TargetKafkaClusterArn=source_arn,
            TopicReplication={
                "TopicsToReplicate": ["sim2real-behav-topic-.*"],
                "TopicsToExclude": [],
                "CopyTopicConfigurations": True,
                "CopyAccessControlListsForTopics": False,
                "DetectAndCopyNewTopics": False,
            },
        )
    )
    expected = (
        "BadRequestException",
        "The replication info specified with the kafka cluster aliases does not exist.",
    )
    assert code == expected, (
        f"expected UpdateReplicationInfo with a swapped source/target pair to be rejected with "
        f"{expected!r}, got {code!r}"
    )

    after = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    assert after["CurrentVersion"] == good_version, (
        f"a rejected update must not bump CurrentVersion: expected {good_version!r}, "
        f"got {after['CurrentVersion']!r}"
    )
    alias_of = _arn_to_alias(after, source_arn, target_arn)
    info_list = after["ReplicationInfoList"]
    assert any(
        r.get("SourceKafkaClusterAlias") == alias_of[source_arn]
        and r.get("TargetKafkaClusterAlias") == alias_of[target_arn]
        for r in info_list
    ), f"expected the original source->target entry to remain configured, got {info_list!r}"
    assert not any(
        r.get("SourceKafkaClusterAlias") == alias_of[target_arn]
        and r.get("TargetKafkaClusterAlias") == alias_of[source_arn]
        for r in info_list
    ), f"the swapped pair must never appear as a stored replication-info entry, got {info_list!r}"
    unchanged_topic_repl = _topic_replication_of(after, source_arn, target_arn)
    assert unchanged_topic_repl["DetectAndCopyNewTopics"] is True, (
        f"the rejected update must not have changed DetectAndCopyNewTopics away from the "
        f"positive control's True, got {unchanged_topic_repl!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected the swapped-pair UpdateReplicationInfo call to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _arn_to_alias(describe_resp, *arns):
    """DescribeReplicator identifies clusters by KafkaClusterAlias, not ARN -- ReplicationInfoList
    entries carry only Source/TargetKafkaClusterAlias. Map each requested ARN to its alias via the
    response's own KafkaClusters list."""
    by_arn = {
        c["AmazonMskCluster"]["MskClusterArn"]: c["KafkaClusterAlias"]
        for c in describe_resp["KafkaClusters"]
    }
    missing = [a for a in arns if a not in by_arn]
    if missing:
        raise AssertionError(f"no KafkaClusterAlias found for {missing} in {describe_resp!r}")
    return by_arn


def _topic_replication_of(describe_resp, source_arn, target_arn):
    alias_of = _arn_to_alias(describe_resp, source_arn, target_arn)
    for r in describe_resp["ReplicationInfoList"]:
        if (
            r.get("SourceKafkaClusterAlias") == alias_of[source_arn]
            and r.get("TargetKafkaClusterAlias") == alias_of[target_arn]
        ):
            return r["TopicReplication"]
    raise AssertionError(
        f"no ReplicationInfoList entry found for {source_arn} -> {target_arn} in {describe_resp!r}"
    )


def _network_subnets_sg(ctx):
    """The run's shared network: its VPC, two of its subnets and its default security group.

    The network has one subnet per standard availability zone, so two of them are in distinct
    standard AZs, which MSK requires to place brokers.
    """
    net = ctx.network()
    return net.vpc_id, net.subnet_ids[:2], net.security_group_id


def _create_serverless_cluster(ctx, subnet_ids, sg_id):
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-srvless-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Serverless={
            "VpcConfigs": [{"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}],
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: kafka.delete_cluster(ClusterArn=cluster_arn))
    _wait_cluster_v2_active(ctx, cluster_arn)
    return cluster_arn


def _wait_cluster_v2_active(ctx, cluster_arn, timeout_s=1800.0, interval_s=30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not become ACTIVE within {timeout_s}s")


def _create_replicator_execution_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-msk-replicator-role-")
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
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _create_replicator(ctx, source_arn, target_arn, subnet_ids, sg_id):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-replicator-")
    role_arn = _create_replicator_execution_role(ctx)
    kwargs = dict(
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
        ReplicationInfoList=[
            {
                "SourceKafkaClusterArn": source_arn,
                "TargetKafkaClusterArn": target_arn,
                # Required by botocore's client-side validation.
                "TargetCompressionType": "NONE",
                "TopicReplication": {
                    "TopicsToReplicate": ["sim2real-behav-topic-.*"],
                    "CopyTopicConfigurations": True,
                    "CopyAccessControlListsForTopics": False,
                    "DetectAndCopyNewTopics": False,
                },
                "ConsumerGroupReplication": {
                    "ConsumerGroupsToReplicate": ["sim2real-behav-cg-.*"],
                    "DetectAndCopyNewConsumerGroups": False,
                    "SynchroniseConsumerGroupOffsets": False,
                },
            }
        ],
        Tags={"sim2real:managed": "true"},
    )

    # The role's trust policy takes a few seconds to propagate before kafka.amazonaws.com can assume
    # it; retry (bounded) only role-trust errors, since anything else is a real rejection.
    deadline = time.monotonic() + 90.0
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = kafka.create_replicator(**kwargs)
            break
        except ClientError as exc:
            last_exc = exc
            msg = str(exc)
            if "role" not in msg.lower() and "assume" not in msg.lower():
                raise
            time.sleep(5.0)
    if resp is None:
        raise AssertionError(
            f"CreateReplicator did not succeed within 90s of role creation "
            f"(role trust propagation): {last_exc}"
        )
    replicator_arn = resp["ReplicatorArn"]
    ctx.on_cleanup(lambda: kafka.delete_replicator(ReplicatorArn=replicator_arn))
    return replicator_arn


def _wait_replicator_state(ctx, replicator_arn, target_state, timeout_s=3600.0, interval_s=30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        last = info["ReplicatorState"]
        if last == target_state:
            return info
        if last == "FAILED":
            raise AssertionError(f"replicator {replicator_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(
        f"replicator {replicator_arn} did not reach {target_state} within {timeout_s}s (last={last})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
