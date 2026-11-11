"""update-replication-info-invalid-topic-pattern-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-replication-info-invalid-topic-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReplicationInfo with an invalid TopicsToReplicate regex ("[") is rejected with the
    exact BadRequestException and leaves state, CurrentVersion and topics unchanged; a valid
    pattern is then applied once the replicator returns to RUNNING."""
    replicator_arn, source_arn, target_arn = _create_replication_pair(ctx)
    kafka = ctx.client("kafka")

    before = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    before_version = before["CurrentVersion"]
    before_topics = _topics_to_replicate(before, source_arn, target_arn)
    assert before_topics == [".*"], f"expected the freshly created replicator's TopicsToReplicate to be ['.*'], got {before_topics!r}"

    def _update_bad():
        return kafka.update_replication_info(
            ReplicatorArn=replicator_arn,
            CurrentVersion=before_version,
            SourceKafkaClusterArn=source_arn,
            TargetKafkaClusterArn=target_arn,
            TopicReplication={
                "TopicsToReplicate": ["["],
                "TopicsToExclude": [],
                "CopyTopicConfigurations": True,
                # MSK Serverless clusters do not support ACLs (True is rejected with
                # InvalidInput.InvalidTopicReplication).
                "CopyAccessControlListsForTopics": False,
                "DetectAndCopyNewTopics": True,
            },
        )

    code = _error_code(_update_bad)
    expected = ("BadRequestException", 'The regex "[" is invalid.')
    assert code == expected, f"unterminated character class: expected {expected!r}, got {code!r}"

    unchanged = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    assert unchanged["ReplicatorState"] == "RUNNING", f"expected ReplicatorState to remain RUNNING after the rejected update, got {unchanged['ReplicatorState']!r}"
    assert unchanged["CurrentVersion"] == before_version, f"expected CurrentVersion to stay at {before_version!r} after the rejected update, got {unchanged['CurrentVersion']!r}"
    unchanged_topics = _topics_to_replicate(unchanged, source_arn, target_arn)
    assert unchanged_topics == [".*"], f"expected TopicsToReplicate to remain ['.*'] after the rejected update, got {unchanged_topics!r}"

    # A valid pattern is accepted and actually applied.
    kafka.update_replication_info(
        ReplicatorArn=replicator_arn,
        CurrentVersion=before_version,
        SourceKafkaClusterArn=source_arn,
        TargetKafkaClusterArn=target_arn,
        TopicReplication={
            "TopicsToReplicate": ["sim2real-valid-.*"],
            "TopicsToExclude": [],
            "CopyTopicConfigurations": True,
            "CopyAccessControlListsForTopics": False,
            "DetectAndCopyNewTopics": True,
        },
    )
    after = _wait_replicator_state(ctx, replicator_arn, {"RUNNING"}, timeout_s=1800)
    assert after["CurrentVersion"] != before_version, f"expected CurrentVersion to change from {before_version!r} after the valid update was applied"
    after_topics = _topics_to_replicate(after, source_arn, target_arn)
    assert after_topics == ["sim2real-valid-.*"], f"expected TopicsToReplicate to become ['sim2real-valid-.*'], got {after_topics!r}"


# ===== helpers =====
def _cluster_arn_by_alias(described):
    """ReplicationInfoList entries key clusters by alias, not ARN; resolve the ARN through the
    KafkaClusters list, which carries both."""
    out = {}
    for cluster in described["KafkaClusters"]:
        alias = cluster.get("KafkaClusterAlias")
        arn = cluster.get("AmazonMskCluster", {}).get("MskClusterArn")
        if alias and arn:
            out[alias] = arn
    return out


def _topics_to_replicate(described, source_arn, target_arn):
    by_alias = _cluster_arn_by_alias(described)
    for info in described["ReplicationInfoList"]:
        src = by_alias.get(info.get("SourceKafkaClusterAlias"))
        tgt = by_alias.get(info.get("TargetKafkaClusterAlias"))
        if src == source_arn and tgt == target_arn:
            return info["TopicReplication"]["TopicsToReplicate"]
    raise AssertionError("could not find the source->target replication flow in ReplicationInfoList")


def _default_vpc_subnets_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to provision MSK test clusters in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if len(subnets) < 2:
        raise AssertionError("shared network does not have >=2 default-for-az subnets to provision MSK Serverless clusters in")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets[:2]], sg


def _create_serverless_cluster(ctx, name, subnet_ids, sg_id):
    # Serverless, not Provisioned: MSK Replicator refuses a Provisioned cluster with fewer than 3
    # brokers (InvalidInput.InvalidKafkaCluster); Serverless also avoids ~20 min settle per cluster.
    kafka = ctx.client("kafka")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Serverless={
            "VpcConfigs": [{"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}],
            # Required for a Serverless body (omitting it is an "Invalid request body"
            # BadRequestException); the replicator needs IAM access control on both clusters.
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_ignore(ctx, arn))
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=300, interval_s=10)
    return arn


def _delete_cluster_ignore(ctx, arn):
    try:
        ctx.client("kafka").delete_cluster(ClusterArn=arn)
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


def _create_replicator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kafka-repl-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole")
    return role_arn


def _delete_role_ignore(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for attached in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=attached["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_replication_pair(ctx):
    kafka = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets_sg(ctx)
    # The role is created before either cluster: the cluster creates outlast IAM propagation, so no
    # separate wait is needed for kafka.amazonaws.com to see the role.
    role_arn = _create_replicator_role(ctx)
    source_arn = _create_serverless_cluster(ctx, ctx.unique_name("sim2real-kafka-repsrc-"), subnet_ids, sg_id)
    target_arn = _create_serverless_cluster(ctx, ctx.unique_name("sim2real-kafka-reptgt-"), subnet_ids, sg_id)

    replicator_name = ctx.unique_name("sim2real-kafka-replicator-")
    resp = kafka.create_replicator(
        ReplicatorName=replicator_name,
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
                "TargetCompressionType": "NONE",
                "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
                # CopyAccessControlListsForTopics defaults to true when omitted, and Serverless
                # clusters reject true outright.
                "TopicReplication": {"TopicsToReplicate": [".*"], "CopyAccessControlListsForTopics": False},
            }
        ],
        Tags={"sim2real:managed": "true"},
    )
    replicator_arn = resp["ReplicatorArn"]
    ctx.on_cleanup(lambda: _delete_replicator(ctx, replicator_arn))
    # MSK Replicator CREATING -> RUNNING can take up to ~40 minutes even with both clusters ACTIVE.
    _wait_replicator_state(ctx, replicator_arn, {"RUNNING"}, timeout_s=2700)
    return replicator_arn, source_arn, target_arn


def _delete_replicator(ctx, replicator_arn):
    # MSK refuses DeleteReplicator with BadRequestException while the replicator is still applying
    # an update, so retry exactly that to a bounded deadline; not-found is done, the rest raises.
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + 300
    while True:
        try:
            kafka.delete_replicator(ReplicatorArn=replicator_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_replicator_state(ctx, replicator_arn, ok_states, *, timeout_s, interval_s=10):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        last = info["ReplicatorState"]
        if last in ok_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"replicator entered FAILED state while waiting for {ok_states}: {info.get('StateInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"replicator did not reach {ok_states} within {timeout_s}s (last state={last})")


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if it raises.

    An unexpected success raises, so an over-permissive accept is not reported as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the malformed-regex update to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
