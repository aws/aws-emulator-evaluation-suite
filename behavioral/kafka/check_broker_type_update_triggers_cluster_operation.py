"""broker-type-update-triggers-cluster-operation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "broker-type-update-triggers-cluster-operation"
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBrokerType enqueues a trackable cluster operation: the cluster moves to UPDATING,
    the operation shows up in ListClusterOperations, and DescribeClusterOperation tracks it to
    UPDATE_COMPLETE while the cluster returns to ACTIVE with the new instance type."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_active_cluster(ctx, num_brokers=2, instance_type="kafka.t3.small")

    before = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    current_version = before["CurrentVersion"]
    assert before["BrokerNodeGroupInfo"]["InstanceType"] == "kafka.t3.small"

    resp = kafka.update_broker_type(
        ClusterArn=cluster_arn, CurrentVersion=current_version, TargetInstanceType="kafka.m5.large"
    )
    op_arn = resp["ClusterOperationArn"]

    mid = _poll_cluster_leaves_active(kafka, cluster_arn)
    assert mid["State"] == "UPDATING", f"expected cluster State UPDATING after UpdateBrokerType, got {mid['State']}"

    # ListClusterOperations names each operation's ARN OperationArn: the model's
    # ClusterOperationInfo has no ClusterOperationArn member, and reading that key raised KeyError
    # on real AWS. UpdateBrokerType's own response does call it ClusterOperationArn.
    ops = [o["OperationArn"] for o in kafka.list_cluster_operations(ClusterArn=cluster_arn).get(
        "ClusterOperationInfoList", []
    )]
    assert op_arn in ops, "UpdateBrokerType operation must be listed in ListClusterOperations"

    # A two-broker t3.small -> m5.large rolling update ran past 2700 s on real AWS.
    final_op = _wait_operation_state(ctx, op_arn, {"UPDATE_COMPLETE", "UPDATE_FAILED"}, timeout_s=4800)
    assert final_op["OperationState"] == "UPDATE_COMPLETE", f"broker type update did not complete: {final_op}"

    after = _wait_cluster_state_full(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=600)
    assert after["State"] == "ACTIVE"
    assert after["BrokerNodeGroupInfo"]["InstanceType"] == "kafka.m5.large"


def _poll_cluster_leaves_active(msk, cluster_arn, timeout_s=120.0, interval_s=3.0):
    """The cluster's ClusterInfo at its first read whose State is not ACTIVE; the update's
    state change is asynchronous, so the first read after the call may still be ACTIVE."""
    deadline = time.monotonic() + timeout_s
    while True:
        info = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        if info["State"] != "ACTIVE" or time.monotonic() >= deadline:
            return info
        time.sleep(interval_s)


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return True
        raise
    return False


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


def _wait_operation_state(ctx, op_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        if last["OperationState"] in target_states:
            return last
        time.sleep(interval_s)
    raise _never_ready(
        f"cluster operation did not reach {target_states} within {timeout_s}s (last={last})",
    )


def _create_active_cluster(ctx, num_brokers=2, security_group_ids=None, instance_type="kafka.t3.small", timeout_s=3000):
    # A two-broker kafka.t3.small cluster was measured past 1800 s in CREATING on real AWS.
    kafka = ctx.client("kafka")
    net = ctx.network()
    # Standard brokers accept 3.9.x; 4.2.x runs on Express brokers only.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    sg_ids = security_group_ids if security_group_ids is not None else [net.security_group_id]
    cluster_arn = kafka.create_cluster(
        ClusterName=ctx.unique_name("sim2real-msk-"),
        KafkaVersion="3.9.x",
        NumberOfBrokerNodes=num_brokers,
        BrokerNodeGroupInfo={
            "InstanceType": instance_type,
            "ClientSubnets": net.subnet_ids[:num_brokers],
            "SecurityGroups": sg_ids,
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
    )["ClusterArn"]

    def _cleanup():
        # DeleteCluster is refused while the cluster is UPDATING ("You can't delete cluster in
        # UPDATING state", observed on real AWS), so let a running operation settle first (bounded:
        # if it does not, the delete below reports the refusal).
        try:
            _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=900)
        except AssertionError:
            pass
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        deadline = time.monotonic() + 800
        while time.monotonic() < deadline:
            if _gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
                return
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still present 800s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
