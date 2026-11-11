"""cluster-storage-rebalancing-replication-updates-blocked-while-creating."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-storage-rebalancing-replication-updates-blocked-while-creating"
GROUP = "state-machine"
SERVICES = ["kafka"]

# Prefixes the failure of a resource the target accepted but never converged to its ready state,
# so it reads as a state-machine failure rather than a connection or not-implemented error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStorage and UpdateRebalancing are rejected while the cluster is still CREATING.

    The same UpdateRebalancing succeeds once the cluster is ACTIVE (positive control), and
    UpdateReplicationInfo refuses a ReplicatorArn that does not resolve to a real replicator.
    """
    kafka = ctx.client("kafka")
    # UpdateRebalancing applies to Express brokers only (MSK API reference: "update the
    # intelligent rebalancing status of an Amazon MSK Provisioned cluster with Express brokers"),
    # so the cluster is a three-broker Express cluster; Express brokers accept Kafka 3.8.x.
    net = ctx.network()
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.8.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.8.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=ctx.unique_name("sim2real-msk-"),
        Provisioned={
            "KafkaVersion": "3.8.x",
            "NumberOfBrokerNodes": 3,
            "BrokerNodeGroupInfo": {
                "InstanceType": "express.m7g.large",
                "ClientSubnets": net.subnet_ids[:3],
                "SecurityGroups": [net.security_group_id],
            },
        },
        Tags={"sim2real:managed": "true"},
    )["ClusterArn"]

    def _cleanup():
        # DeleteCluster is refused while the cluster is CREATING or a rebalancing operation runs
        # ("You can't delete cluster in CREATING state", observed on real AWS), so let it settle
        # first (bounded: if it does not, the delete below reports the refusal).
        try:
            _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=1500)
        except AssertionError:
            pass
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        # The delete was accepted; the cluster has no dependants here, so it is not waited out.

    ctx.on_cleanup(_cleanup)

    # Everything the CREATING window shows is observed first and asserted once the cluster is
    # ACTIVE: DeleteCluster is refused while a cluster is CREATING ("You can't delete cluster in
    # CREATING state", observed on real AWS), so a verdict reached earlier would leave a teardown
    # that cannot run.
    info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    current_version = info["CurrentVersion"]

    storage_code, _storage_message = _error_code(
        lambda: kafka.update_storage(
            ClusterArn=cluster_arn,
            CurrentVersion=current_version,
            StorageMode="LOCAL",
            ProvisionedThroughput={"Enabled": False},
        )
    )

    rebalancing_code, rebalancing_message = _error_code(
        lambda: kafka.update_rebalancing(
            ClusterArn=cluster_arn, CurrentVersion=current_version, Rebalancing={"Status": "PAUSED"}
        )
    )

    # The cluster must genuinely be unaffected by the rejected calls.
    still_creating = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]

    # UpdateReplicationInfo enforces the analogous "target not usable yet" guard: a
    # syntactically valid ReplicatorArn that does not resolve to any replicator is rejected
    # rather than accepted as a no-op. Real AWS answers it with BadRequestException "Invalid
    # parameter currentVersion.": the version is checked against a replicator that does not exist.
    # A replicator ARN has the shape arn:aws:kafka:<region>:<account>:replicator/<name>/<uuid>-<n>;
    # the cluster ARN with its resource type swapped is not one (real AWS answered it with
    # BadRequestException), so the never-issued ARN is built in the replicator's own shape.
    arn_prefix = cluster_arn.split(":cluster/")[0]
    fake_replicator_arn = f"{arn_prefix}:replicator/{ctx.unique_name('sim2real-ghost-repl-')}/{uuid.uuid4()}-4"
    replication_code, replication_message = _error_code(
        lambda: kafka.update_replication_info(
            ReplicatorArn=fake_replicator_arn,
            CurrentVersion="1",
            SourceKafkaClusterArn=cluster_arn,
            TargetKafkaClusterArn=cluster_arn,
            # UpdateReplicationInfo has no TargetCompressionType member; a consumer-group filter
            # change is a well-formed update.
            ConsumerGroupReplication={
                "ConsumerGroupsToReplicate": [".*"],
                "ConsumerGroupsToExclude": [],
                "DetectAndCopyNewConsumerGroups": True,
                "SynchroniseConsumerGroupOffsets": False,
            },
        )
    )

    active_info = _wait_cluster_state_full(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=3600)
    assert active_info["State"] == "ACTIVE", f"cluster never became ACTIVE: {active_info}"

    assert info["State"] == "CREATING", f"expected freshly-created cluster to be CREATING, got {info['State']}"
    assert storage_code == "BadRequestException", f"expected BadRequestException for UpdateStorage on a CREATING cluster, got {storage_code}"
    assert rebalancing_code == "BadRequestException", (
        f"expected BadRequestException for UpdateRebalancing on a CREATING cluster, got {rebalancing_code}"
    )
    assert rebalancing_message == (
        "This operation is only valid for resources that are in one of the following states :[ACTIVE]"
    ), f"UpdateRebalancing message: {rebalancing_message!r}"
    assert still_creating["State"] == "CREATING"
    assert still_creating["CurrentVersion"] == current_version
    assert replication_code == "BadRequestException", f"expected BadRequestException for a nonexistent replicator, got {replication_code}"
    assert replication_message == "Invalid parameter currentVersion.", (
        f"UpdateReplicationInfo message: {replication_message!r}"
    )

    # Positive control: once the cluster actually reaches ACTIVE, the identical kind of
    # mutating update call is accepted (proving the earlier rejections were the CREATING guard,
    # not a permanently broken request shape).
    active_version = active_info["CurrentVersion"]
    # Express clusters start with rebalancing ACTIVE, so PAUSED is a real change.
    resp = kafka.update_rebalancing(
        ClusterArn=cluster_arn, CurrentVersion=active_version, Rebalancing={"Status": "PAUSED"}
    )
    assert resp["ClusterOperationArn"], "UpdateRebalancing on an ACTIVE cluster must enqueue a cluster operation"


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


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


def _wait_cluster_state_full(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        if last["State"] in target_states:
            return last
        time.sleep(interval_s)
    raise _never_ready(
        f"cluster did not reach {target_states} within {timeout_s}s (last={last})",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

