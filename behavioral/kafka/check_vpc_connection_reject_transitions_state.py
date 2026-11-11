"""vpc-connection-reject-transitions-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-connection-reject-transitions-state"
GROUP = "state-machine"
SERVICES = ["kafka"]

# Marks a control-plane convergence failure: a state machine the target accepted but never drove
# to its ready state is a failure of the target, not a network problem of the caller.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RejectClientVpcConnection moves an AVAILABLE client VPC connection to REJECTED and it no
    longer appears as an active connection; the reject is valid only for AVAILABLE, so the
    connection reaches AVAILABLE first."""
    kafka = ctx.client("kafka")
    cluster_arn, subnets, sg_id = _create_active_cluster_with_vpc_connectivity(ctx)

    resp = kafka.create_vpc_connection(
        TargetClusterArn=cluster_arn,
        Authentication="SASL_IAM",
        VpcId=ctx.network().vpc_id,
        ClientSubnets=subnets,
        SecurityGroups=[sg_id],
    )
    vpc_conn_arn = resp["VpcConnectionArn"]
    assert resp["State"] == "CREATING"
    ctx.on_cleanup(lambda: _delete_vpc_connection_ignore_missing(ctx, vpc_conn_arn))

    pending = [c["VpcConnectionArn"] for c in kafka.list_client_vpc_connections(ClusterArn=cluster_arn).get(
        "ClientVpcConnections", []
    )]
    assert vpc_conn_arn in pending, "the newly created VPC connection request must be listed for the cluster"

    deadline = time.monotonic() + 1800
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_vpc_connection(Arn=vpc_conn_arn)["State"]
        if state in ("AVAILABLE", "FAILED"):
            break
        time.sleep(2)
    if state != "AVAILABLE":
        raise _never_ready(f"VPC connection {vpc_conn_arn} did not reach AVAILABLE within 1800s (last {state})")

    kafka.reject_client_vpc_connection(ClusterArn=cluster_arn, VpcConnectionArn=vpc_conn_arn)

    deadline = time.monotonic() + 300
    final_state = None
    while time.monotonic() < deadline:
        final_state = kafka.describe_vpc_connection(Arn=vpc_conn_arn)["State"]
        if final_state in ("REJECTED", "AVAILABLE", "FAILED"):
            break
        time.sleep(2)
    assert final_state == "REJECTED", f"expected VPC connection to settle as REJECTED, got {final_state}"

    active = [
        c["VpcConnectionArn"]
        for c in kafka.list_client_vpc_connections(ClusterArn=cluster_arn).get("ClientVpcConnections", [])
        # ClientVpcConnection names its state "State".
        if c.get("State") == "AVAILABLE"
    ]
    assert vpc_conn_arn not in active, "rejected VPC connection must not appear as an active connection"


# ===== helpers =====

def _gone(fn) -> bool:
    """True when fn() answers NotFoundException, False when it succeeds; any other error raises."""
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


def _create_active_cluster_with_vpc_connectivity(ctx, num_brokers=2, timeout_s=1800):
    """An IAM-authenticated Standard cluster with multi-VPC private connectivity turned on.

    CreateCluster refuses enabled VpcConnectivity auth at create time ("all vpcConnectivity auth
    schemes must be disabled ... You can enable auth schemes after the cluster is created"),
    so it is turned on with UpdateConnectivity once the cluster is ACTIVE.
    Multi-VPC private connectivity does not support kafka.t3.small brokers, so the brokers are
    kafka.m5.large on Kafka 3.9.x, which Standard brokers accept.
    """
    kafka = ctx.client("kafka")
    net = ctx.network()
    subnets, sg_id = net.subnet_ids[:num_brokers], net.security_group_id
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    name = ctx.unique_name("sim2real-msk-")
    cluster_arn = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion="3.9.x",
        NumberOfBrokerNodes=num_brokers,
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnets,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
    )["ClusterArn"]

    def _cleanup():
        # DeleteCluster is refused while an operation such as UpdateConnectivity runs, so wait for
        # it to settle first (bounded: if it does not, the delete below reports the refusal).
        try:
            _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=600)
        except AssertionError:
            pass
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if _gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
                return
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still present 900s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    _enable_multi_vpc(ctx, cluster_arn)
    return cluster_arn, subnets, sg_id


def _enable_multi_vpc(ctx, cluster_arn: str, timeout_s: float = 4800.0, interval_s: float = 30.0) -> None:
    """Turn on multi-VPC private connectivity (IAM) with UpdateConnectivity and wait for the
    operation; a 2-broker UPDATE_CONNECTIVITY can take over 50 minutes."""
    kafka = ctx.client("kafka")
    current_version = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]
    op_arn = kafka.update_connectivity(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version,
        ConnectivityInfo={"VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}}},
    )["ClusterOperationArn"]
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_operation_v2(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        state = info.get("OperationState", "")
        if state == "UPDATE_COMPLETE":
            return
        if state in ("UPDATE_FAILED", "FAILED"):
            raise AssertionError(f"UpdateConnectivity {op_arn} ended {state}: {info.get('ErrorInfo')}")
        time.sleep(interval_s)
    raise _never_ready(f"UpdateConnectivity {op_arn} did not complete within {timeout_s}s (last {state})")


def _delete_vpc_connection_ignore_missing(ctx, vpc_conn_arn, timeout_s=1200.0, interval_s=15.0):
    """DeleteVpcConnection is refused outside AVAILABLE, FAILED, INACTIVE and REJECTED, so this
    waits for one of those first, then until the connection is gone."""
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_vpc_connection(Arn=vpc_conn_arn).get("State")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state in ("AVAILABLE", "FAILED", "INACTIVE", "REJECTED"):
            kafka.delete_vpc_connection(Arn=vpc_conn_arn)
            break
        if state in ("DELETING", "DEACTIVATING"):
            break
        time.sleep(interval_s)
    else:
        raise AssertionError(f"VPC connection {vpc_conn_arn} never reached a deletable state (last {state})")
    while time.monotonic() < deadline:
        if _gone(lambda: kafka.describe_vpc_connection(Arn=vpc_conn_arn)):
            return
        time.sleep(interval_s)
    raise AssertionError(f"VPC connection {vpc_conn_arn} still present {timeout_s}s after DeleteVpcConnection")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
