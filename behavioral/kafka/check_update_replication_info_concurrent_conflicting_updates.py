"""update-replication-info-concurrent-conflicting-updates."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "update-replication-info-concurrent-conflicting-updates"
GROUP = "concurrency"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateReplicationInfo calls sharing the same stale CurrentVersion
    resolve deterministically: exactly one wins, the loser is rejected as stale, and
    DescribeReplicator reflects only the winner's configuration -- never a merge."""
    # MSK Replicator needs at least three brokers in both clusters, and refuses source and target
    # subnets that only partly overlap ("Keep it distinct or have complete overlap", observed on
    # real AWS), so both clusters use the same three subnets.
    clusters_gone = []
    ctx.on_cleanup(lambda: _wait_for_clusters_deleted(ctx, clusters_gone))
    source_arn, source_subnets, source_sg = _create_provisioned_cluster(ctx, clusters_gone, num_brokers=3)
    target_arn, target_subnets, target_sg = _create_provisioned_cluster(ctx, clusters_gone, num_brokers=3)
    role_arn = _create_replicator_role(ctx)

    kafka = ctx.client("kafka")
    replicator_name = ctx.unique_name("sim2real-behav-repl-")

    def _try_create():
        return kafka.create_replicator(
            ReplicatorName=replicator_name,
            ServiceExecutionRoleArn=role_arn,
            KafkaClusters=[
                {
                    "AmazonMskCluster": {"MskClusterArn": source_arn},
                    "VpcConfig": {"SubnetIds": source_subnets, "SecurityGroupIds": [source_sg]},
                },
                {
                    "AmazonMskCluster": {"MskClusterArn": target_arn},
                    "VpcConfig": {"SubnetIds": target_subnets, "SecurityGroupIds": [target_sg]},
                },
            ],
            ReplicationInfoList=[
                {
                    "SourceKafkaClusterArn": source_arn,
                    "TargetKafkaClusterArn": target_arn,
                    "TargetCompressionType": "NONE",
                    # No exclude lists: CreateReplicator answers "Too many or too few topics
                    # specified" for one that also sends empty exclude lists.
                    "TopicReplication": {
                        "TopicsToReplicate": [".*"],
                        "CopyTopicConfigurations": True,
                        "CopyAccessControlListsForTopics": False,
                        "DetectAndCopyNewTopics": True,
                    },
                    "ConsumerGroupReplication": {
                        "ConsumerGroupsToReplicate": ["seed-group.*"],
                        "DetectAndCopyNewConsumerGroups": True,
                        "SynchroniseConsumerGroupOffsets": False,
                    },
                }
            ],
        )

    # The service execution role trust needs a few seconds of IAM propagation before
    # kafka.amazonaws.com can assume it.
    create_resp = _retry_until(
        _try_create,
        acceptable_codes={"ForbiddenException", "BadRequestException"},
        timeout_s=120,
    )
    replicator_arn = create_resp["ReplicatorArn"]
    ctx.on_cleanup(lambda: _delete_replicator(ctx, replicator_arn))
    _wait_for_replicator_state(ctx, replicator_arn, {"RUNNING"}, timeout_s=1800)

    current_version = kafka.describe_replicator(ReplicatorArn=replicator_arn)["CurrentVersion"]

    def _update(group_pattern):
        return kafka.update_replication_info(
            ReplicatorArn=replicator_arn,
            CurrentVersion=current_version,
            # Required: real AWS refuses an update without them ("Must specify either
            # sourceKafkaClusterArn or sourceKafkaClusterId for the source cluster").
            SourceKafkaClusterArn=source_arn,
            TargetKafkaClusterArn=target_arn,
            ConsumerGroupReplication={
                "ConsumerGroupsToReplicate": [group_pattern],
                "ConsumerGroupsToExclude": [],
                "DetectAndCopyNewConsumerGroups": True,
                "SynchroniseConsumerGroupOffsets": False,
            },
        )

    results = {}

    def _call(label, group_pattern):
        try:
            _update(group_pattern)
            results[label] = ("ok", group_pattern)
        except Exception as err:  # noqa: BLE001 - capturing ClientError code below
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                results[label] = ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))
            else:
                raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_call, "a", "group-a.*")
        f2 = pool.submit(_call, "b", "group-b.*")
        f1.result()
        f2.result()

    outcomes = [results["a"], results["b"]]
    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner among concurrent updates, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one rejected update, got {outcomes}"
    assert failures[0][1] == "BadRequestException", (
        f"expected the stale-version loser to be rejected with BadRequestException, got {failures[0][1]}"
    )
    assert failures[0][2] == (
        "Invalid parameter currentVersion: The version of the connector isn\u2019t current. Check the "
        "current version and try again."
    ), f"stale-version loser's message: {failures[0][2]!r}"

    winning_pattern = successes[0][1]
    _wait_for_replicator_state(ctx, replicator_arn, {"RUNNING"}, timeout_s=600)
    described = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    live_patterns = described["ReplicationInfoList"][0]["ConsumerGroupReplication"]["ConsumerGroupsToReplicate"]
    assert live_patterns == [winning_pattern], (
        f"DescribeReplicator shows {live_patterns}, expected exactly the winner's {[winning_pattern]} "
        "with no trace of the rejected update"
    )


def _retry_until(fn, acceptable_codes, timeout_s=120, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in acceptable_codes or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _active_kafka_version(ctx):
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    kafka = ctx.client("kafka")
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _wait_for_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info.get("State")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_states}; last observed state={last}")


def _wait_for_clusters_deleted(ctx, cluster_arns, timeout_s=1200, interval_s=20):
    """Runs after every cluster's DeleteCluster was sent, so both deletes proceed in parallel."""
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    pending = list(cluster_arns)
    while pending and time.monotonic() < deadline:
        for cluster_arn in list(pending):
            try:
                kafka.describe_cluster_v2(ClusterArn=cluster_arn)
            except ClientError as err:
                if err.response["Error"]["Code"] != "NotFoundException":
                    raise
                pending.remove(cluster_arn)
        if pending:
            time.sleep(interval_s)
    if pending:
        raise AssertionError(f"clusters {pending} were not deleted within {timeout_s}s")


def _create_provisioned_cluster(ctx, created, num_brokers=3):
    kafka = ctx.client("kafka")
    net = ctx.network()
    subnets, sg_id = net.subnet_ids[:num_brokers], net.security_group_id
    kafka_version = _active_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
            # MSK Replicator requires IAM access control on both clusters
            # (https://docs.aws.amazon.com/msk/latest/developerguide/msk-replicator-supported-configs.html);
            # without it the replicator went FAILED on real AWS.
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
        },
    )
    cluster_arn = resp["ClusterArn"]
    created.append(cluster_arn)

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=3000)
    return cluster_arn, subnets, sg_id


def _create_replicator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-msk-repl-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole")
        except iam.exceptions.NoSuchEntityException:
            pass
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole")
    return role["Arn"]


def _wait_for_replicator_state(ctx, replicator_arn, target_states, timeout_s=1800, interval_s=15):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        last = info.get("ReplicatorState")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"replicator entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"replicator never reached {target_states}; last observed state={last}")


def _delete_replicator(ctx, replicator_arn, timeout_s=600, interval_s=20):
    """DeleteReplicator is refused while the replicator is CREATING or UPDATING ("You can't delete
    a replicator in UPDATING state", observed on real AWS), so wait for it to settle first; then
    wait until it is gone, because a cluster a replicator still uses cannot be deleted. One
    deadline bounds both waits on purpose, so this teardown and the cluster teardowns after it fit
    the suite's 1800 s cleanup budget; a replicator still present at it raises, and the cluster
    teardowns run regardless."""
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_replicator(ReplicatorArn=replicator_arn).get("ReplicatorState")
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state not in ("CREATING", "UPDATING"):
            break
        time.sleep(interval_s)
    if state != "DELETING":
        kafka.delete_replicator(ReplicatorArn=replicator_arn)
    while time.monotonic() < deadline:
        try:
            kafka.describe_replicator(ReplicatorArn=replicator_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"replicator {replicator_arn} still present {timeout_s}s into its teardown")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
