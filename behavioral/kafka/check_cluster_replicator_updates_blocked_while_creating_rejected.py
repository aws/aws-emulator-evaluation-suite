"""cluster-replicator-updates-blocked-while-creating-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cluster-replicator-updates-blocked-while-creating-rejected"
GROUP = "state-machine"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStorage and UpdateRebalancing on a CREATING cluster and UpdateReplicationInfo on a CREATING
    replicator fail with BadRequestException and the exact state message, while the same updates are
    accepted once the cluster is ACTIVE and the replicator RUNNING."""
    kafka = ctx.client("kafka")

    # fire off two clusters that will later serve as the replicator's source/target, but
    # immediately probe the storage/rebalancing guard against cluster A while it is CREATING
    cluster_a_arn = _start_cluster_create(ctx, "a")
    cluster_b_arn = _start_cluster_create(ctx, "b")

    creating_info = kafka.describe_cluster_v2(ClusterArn=cluster_a_arn)["ClusterInfo"]
    assert creating_info["State"] == "CREATING", creating_info
    version_a_early = creating_info["CurrentVersion"]

    # UpdateStorage must grow a volume by at least 10 GiB ("To update storage, you must increase
    # it by at least 10 GiB"), so both calls ask for 11 GiB over the 1 GiB
    # volume: the CREATING refusal is then not the size rule's.
    storage_code, storage_message = _error_code(lambda: kafka.update_storage(
        ClusterArn=cluster_a_arn, CurrentVersion=version_a_early, VolumeSizeGB=11
    ))
    assert storage_code == "BadRequestException", f"expected BadRequestException, got {storage_code}"
    assert storage_message == (
        "This operation is only valid for resources that are in one of the following states :[ACTIVE]"
    ), f"UpdateStorage message: {storage_message!r}"

    rebalancing_code, rebalancing_message = _error_code(lambda: kafka.update_rebalancing(
        ClusterArn=cluster_a_arn, CurrentVersion=version_a_early, Rebalancing={"Status": "ACTIVE"}
    ))
    assert rebalancing_code == "BadRequestException", f"expected BadRequestException, got {rebalancing_code}"
    assert rebalancing_message == (
        "This operation is only valid for resources that are in one of the following states :[ACTIVE]"
    ), f"UpdateRebalancing message: {rebalancing_message!r}"

    # both clusters must still exist and be genuinely unaffected -- not just "still non-terminal"
    # but the exact same version the rejected calls would have had to bump to take effect.
    unaffected = kafka.describe_cluster_v2(ClusterArn=cluster_a_arn)["ClusterInfo"]
    assert unaffected["State"] in ("CREATING", "ACTIVE"), unaffected
    assert unaffected["CurrentVersion"] == version_a_early, (
        f"CurrentVersion changed from {version_a_early} to {unaffected['CurrentVersion']} despite "
        "both UpdateStorage and UpdateRebalancing being rejected"
    )

    # Wait for both clusters concurrently rather than sequentially -- each provisioning can take
    # ~15-20 minutes on real AWS, and waiting for them back-to-back risks blowing the overall
    # check timeout even though the two clusters are provisioning in parallel on the service side.
    _wait_for_clusters_active(ctx, [cluster_a_arn, cluster_b_arn])

    # Positive control: once cluster A actually reaches ACTIVE, the identical mutating calls that
    # were rejected above are now accepted -- proving those rejections were the CREATING guard,
    # not a permanently broken request shape.
    active_a = kafka.describe_cluster_v2(ClusterArn=cluster_a_arn)["ClusterInfo"]
    assert active_a["State"] == "ACTIVE", active_a
    active_a_version = active_a["CurrentVersion"]
    storage_resp = kafka.update_storage(
        ClusterArn=cluster_a_arn, CurrentVersion=active_a_version, VolumeSizeGB=11
    )
    assert storage_resp["ClusterOperationArn"], "UpdateStorage on an ACTIVE cluster must enqueue an operation"
    # The storage update leaves cluster A UPDATING; the replicator is built once it has finished.
    _wait_for_operation(kafka, storage_resp["ClusterOperationArn"])

    role_arn = _create_replicator_role(ctx)
    net = ctx.network()
    subnet_ids, sg_id = net.subnet_ids[:3], net.security_group_id
    replicator_name = ctx.unique_name("sim2real-replicator-")
    created = _create_replicator_retrying_role(
        kafka,
        ReplicatorName=replicator_name,
        ServiceExecutionRoleArn=role_arn,
        KafkaClusters=[
            {"AmazonMskCluster": {"MskClusterArn": cluster_a_arn}, "VpcConfig": {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}},
            {"AmazonMskCluster": {"MskClusterArn": cluster_b_arn}, "VpcConfig": {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}},
        ],
        ReplicationInfoList=[{
            "SourceKafkaClusterArn": cluster_a_arn,
            "TargetKafkaClusterArn": cluster_b_arn,
            # Both are required members of ReplicationInfo in the CreateReplicator model.
            "TargetCompressionType": "NONE",
            "TopicReplication": {"TopicsToReplicate": [".*"], "StartingPosition": {"Type": "LATEST"}},
            "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
        }],
        Tags={"sim2real:managed": "true"},
    )
    replicator_arn = created["ReplicatorArn"]
    ctx.on_cleanup(lambda: _delete_replicator(kafka, replicator_arn))

    described = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    assert described["ReplicatorState"] == "CREATING", described
    replicator_version = described["CurrentVersion"]

    replication_code, replication_message = _error_code(lambda: kafka.update_replication_info(
        ReplicatorArn=replicator_arn,
        CurrentVersion=replicator_version,
        SourceKafkaClusterArn=cluster_a_arn,
        TargetKafkaClusterArn=cluster_b_arn,
        TopicReplication=_TOPIC_REPLICATION_UPDATE,
    ))
    assert replication_code == "BadRequestException", f"expected BadRequestException, got {replication_code}"
    assert replication_message == (
        "Invalid parameter replicatorArn: This operation is only valid for resources that are in one "
        "of the following states: [RUNNING]"
    ), f"UpdateReplicationInfo message: {replication_message!r}"

    # Positive control: once the replicator actually reaches RUNNING, the identical kind of
    # UpdateReplicationInfo call is accepted -- proving the rejection above was the CREATING
    # guard, not a permanently malformed request.
    running_info = _wait_for_replicator_state(ctx, replicator_arn, {"RUNNING", "FAILED"})
    assert running_info["ReplicatorState"] == "RUNNING", (
        f"replicator did not reach RUNNING: {running_info}"
    )
    running_version = running_info["CurrentVersion"]
    kafka.update_replication_info(
        ReplicatorArn=replicator_arn,
        CurrentVersion=running_version,
        SourceKafkaClusterArn=cluster_a_arn,
        TargetKafkaClusterArn=cluster_b_arn,
        TopicReplication=_TOPIC_REPLICATION_UPDATE,
    )
    updated_info = _wait_for_replicator_version_change(ctx, replicator_arn, running_version)
    assert updated_info["CurrentVersion"] != running_version, (
        f"CurrentVersion did not change after a successful UpdateReplicationInfo: {updated_info}"
    )


# UpdateReplicationInfo takes no TargetCompressionType (botocore: "Unknown parameter in input:
# TargetCompressionType"); a topic-replication filter change is the update both calls send.
_TOPIC_REPLICATION_UPDATE = {
    "TopicsToReplicate": [".*"],
    "TopicsToExclude": ["sim2real-excluded-.*"],
    "CopyTopicConfigurations": True,
    "CopyAccessControlListsForTopics": False,
    "DetectAndCopyNewTopics": True,
}


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _delete_replicator(kafka, replicator_arn, timeout_s=600.0):
    """DeleteReplicator is refused while the replicator is CREATING or UPDATING ("You can't delete
    a replicator in UPDATING state"), so wait for it to settle first; then
    wait until it is gone, because a cluster a replicator still uses cannot be deleted. One
    deadline bounds both waits. A replicator still CREATING or UPDATING at it is deleted anyway,
    so the refusal is raised as this teardown's failure; the cluster teardowns run regardless."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_replicator(ReplicatorArn=replicator_arn)["ReplicatorState"]
        except kafka.exceptions.NotFoundException:
            return
        if state not in ("CREATING", "UPDATING"):
            break
        time.sleep(20.0)
    if state != "DELETING":
        kafka.delete_replicator(ReplicatorArn=replicator_arn)
    while time.monotonic() < deadline:
        try:
            kafka.describe_replicator(ReplicatorArn=replicator_arn)
        except kafka.exceptions.NotFoundException:
            return
        time.sleep(20.0)
    raise AssertionError(f"replicator {replicator_arn} still present {timeout_s}s into its teardown")


_CLUSTERS: list = []


def _wait_for_operation(kafka, operation_arn, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_operation_v2(ClusterOperationArn=operation_arn)["ClusterOperationInfo"]
        state = info.get("OperationState")
        if state == "UPDATE_COMPLETE":
            return
        if state in ("UPDATE_FAILED", "FAILED"):
            raise AssertionError(f"cluster operation {operation_arn} ended {state}: {info.get('ErrorInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation {operation_arn} did not complete within {timeout_s}s (last {state})")


def _create_replicator_retrying_role(kafka, timeout_s=120.0, **kwargs):
    """kafka.amazonaws.com may not yet be able to assume a just-created role; only a role-shaped
    rejection is retried."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kafka.create_replicator(**kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            if ("role" not in msg and "assume" not in msg) or time.monotonic() >= deadline:
                raise
        time.sleep(5.0)


def _delete_cluster(kafka, cluster_arn, timeout_s=900.0):
    """DeleteCluster is refused while the cluster is CREATING or UPDATING ("You can't delete
    cluster in CREATING state"), so wait for it to settle first (bounded:
    if it does not, the delete reports the refusal)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        except kafka.exceptions.NotFoundException:
            return
        if state not in ("CREATING", "UPDATING"):
            break
        time.sleep(20.0)
    try:
        kafka.delete_cluster(ClusterArn=cluster_arn)
    except kafka.exceptions.NotFoundException:
        pass


def _wait_clusters_deleted(kafka, cluster_arns, timeout_s=1200.0, interval_s=20.0):
    """Runs after every DeleteCluster was sent, so the clusters delete in parallel."""
    deadline = time.monotonic() + timeout_s
    pending = list(cluster_arns)
    while pending and time.monotonic() < deadline:
        for arn in list(pending):
            try:
                kafka.describe_cluster_v2(ClusterArn=arn)
            except kafka.exceptions.NotFoundException:
                pending.remove(arn)
        if pending:
            time.sleep(interval_s)
    if pending:
        raise AssertionError(f"clusters {pending} still present {timeout_s}s after DeleteCluster")


def _wait_for_cluster_active(ctx, cluster_arn, timeout_s=3000.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s (last={last_state})")


def _wait_for_clusters_active(ctx, cluster_arns, timeout_s=3000.0, interval_s=20.0):
    """Poll multiple clusters for ACTIVE concurrently (one shared deadline) instead of waiting
    for each cluster's full provisioning time back-to-back."""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=len(cluster_arns)) as pool:
        results = list(
            pool.map(
                lambda arn: _wait_for_cluster_active(ctx, arn, timeout_s=timeout_s, interval_s=interval_s),
                cluster_arns,
            )
        )
    return results


def _wait_for_replicator_state(ctx, replicator_arn, target_states, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        if last["ReplicatorState"] in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"replicator {replicator_arn} did not reach {target_states} within {timeout_s}s (last={last})"
    )


def _wait_for_replicator_version_change(ctx, replicator_arn, before_version, timeout_s=300.0, interval_s=10.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        if last["ReplicatorState"] == "FAILED":
            raise AssertionError(f"replicator {replicator_arn} entered FAILED state: {last}")
        if last["CurrentVersion"] != before_version:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"replicator {replicator_arn} CurrentVersion did not change from {before_version} "
        f"within {timeout_s}s (last={last})"
    )


def _start_cluster_create(ctx, tag, num_brokers=3):
    kafka = ctx.client("kafka")
    net = ctx.network()
    subnet_ids, sg_id = net.subnet_ids[:3], net.security_group_id
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    name = ctx.unique_name(f"sim2real-msk-{tag}-")
    cluster_arn = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion="3.9.x",
        NumberOfBrokerNodes=num_brokers,
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        Tags={"sim2real:managed": "true"},
    )["ClusterArn"]
    if not _CLUSTERS:
        ctx.on_cleanup(lambda: _wait_clusters_deleted(kafka, _CLUSTERS))
    _CLUSTERS.append(cluster_arn)
    ctx.on_cleanup(lambda: _delete_cluster(kafka, cluster_arn))
    return cluster_arn


def _create_replicator_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-msk-replicator-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "kafka.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    _wait_for_role_policy_attached(iam, role_name, managed_policy_arn)
    return role_arn


def _wait_for_role_policy_attached(iam, role_name, policy_arn, timeout_s=60.0, interval_s=3.0):
    """Bounded poll for the attach to be visible on IAM's own read path, standing in for the
    eventual-consistency window before MSK's own AssumeRole of this role sees it."""
    deadline = time.monotonic() + timeout_s
    attached = []
    while time.monotonic() < deadline:
        attached = [
            p["PolicyArn"]
            for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        ]
        if policy_arn in attached:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"AttachRolePolicy for {policy_arn} on {role_name} not visible within {timeout_s}s (last={attached})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
