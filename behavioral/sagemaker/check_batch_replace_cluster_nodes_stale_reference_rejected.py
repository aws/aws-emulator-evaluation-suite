"""batch-replace-cluster-nodes-stale-reference-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-replace-cluster-nodes-stale-reference-rejected"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchReplaceClusterNodes referencing only a NodeLogicalId already removed by a prior
    BatchDeleteClusterNodes is refused as a whole with ValidationException and the exact
    "All provided nodes do not exist" message, while the cluster keeps accepting unrelated node-add requests."""
    sm = ctx.client("sagemaker")

    role_arn, role_name = _create_execution_role(ctx)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    cluster_name = ctx.unique_name("sim2real-behav-hpc-")

    def _create():
        return sm.create_cluster(
            ClusterName=cluster_name,
            InstanceGroups=[
                {
                    # Real AWS rejects a Slurm-mode cluster with no Controller instance group
                    # ("InstanceGroups must have a SlurmConfig with Controller node type"), on top
                    # of the SlurmConfig requirement below -- so a minimal Continuous/Slurm cluster
                    # needs both a controller and a compute group, not just the compute group this
                    # check actually exercises.
                    "InstanceGroupName": "controller",
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                },
                {
                    "InstanceGroupName": "workers",
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 0,
                    "ExecutionRole": role_arn,
                    # Real AWS rejects NodeProvisioningMode="Continuous" without this: "Cluster ...
                    # has no InstanceGroup with SlurmConfig which is required for Continuous Node
                    # Provisioning Mode clusters" -- contra the Smithy doc string, which claims
                    # Continuous is EKS-only. BatchAdd/Delete/ReplaceClusterNodes (what this check
                    # exercises) are documented as Continuous-only, so this is required.
                    "SlurmConfig": {"NodeType": "Compute", "PartitionNames": ["workers"]},
                },
            ],
            NodeProvisioningMode="Continuous",
            Orchestrator={"Slurm": {}},
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    try:
        _retry_role_propagation(_create)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceLimitExceeded":
            raise AssertionError(
                "account/region has no HyperPod capacity quota for ml.t3.medium - "
                "cannot provision a cluster to exercise node lifecycle"
            ) from exc
        raise
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_name))

    status = _wait_for_cluster_status(sm, cluster_name, {"InService", "Failed"}, timeout_s=1800)
    if status != "InService":
        raise AssertionError(
            f"cluster never reached InService (status={status!r}) in this account/region",
        )

    added = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": "workers", "IncrementTargetCountBy": 1}],
    )
    if not added.get("Successful"):
        raise AssertionError(f"BatchAddClusterNodes could not add a node: {added.get('Failed')}")
    logical_id = added["Successful"][0]["NodeLogicalId"]

    _wait_for_node_presence(sm, cluster_name, logical_id, present=True, timeout_s=600)
    _wait_for_node_running(sm, cluster_name, logical_id, timeout_s=1200)

    sm.batch_delete_cluster_nodes(ClusterName=cluster_name, NodeLogicalIds=[logical_id])
    _wait_for_node_presence(sm, cluster_name, logical_id, present=False, timeout_s=600)

    replace_code, replace_message = _error_response(
        lambda: sm.batch_replace_cluster_nodes(ClusterName=cluster_name, NodeLogicalIds=[logical_id])
    )
    assert replace_code == "ValidationException", (
        f"expected ValidationException for a batch naming only a deleted node, got "
        f"{replace_code}: {replace_message}"
    )
    expected_replace_message = "All provided nodes do not exist. Please check the input and try again."
    assert replace_message == expected_replace_message, (
        f"expected message {expected_replace_message!r}, got {replace_message!r}"
    )

    # Independent read at the destination: the rejected replace must not have
    # materialized a node under the stale reference. list_cluster_nodes is a
    # different operation than the batch_replace_cluster_nodes call being
    # verified, so this cannot be satisfied by that call's own say-so.
    post_replace = sm.list_cluster_nodes(ClusterName=cluster_name)
    assert not any(
        n.get("NodeLogicalId") == logical_id for n in post_replace.get("ClusterNodeSummaries", [])
    ), f"stale NodeLogicalId {logical_id!r} appeared in ListClusterNodes after a rejected replace"

    # Positive control: the same cluster still accepts a fresh node-add
    # request, proving the rejection above is specific to the stale
    # reference and not a blanket failure of the cluster/API.
    control = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": "workers", "IncrementTargetCountBy": 1}],
    )
    assert control.get("Successful"), f"control BatchAddClusterNodes unexpectedly failed: {control}"
    control_logical_id = control["Successful"][0]["NodeLogicalId"]

    # Terminal read, independent of the control's own mutating response: the
    # newly added node must actually become visible via ListClusterNodes,
    # proving the cluster is still genuinely accepting work rather than just
    # echoing a success it never delivers.
    _wait_for_node_presence(sm, cluster_name, control_logical_id, present=True, timeout_s=600)


# ===== helpers =====

def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-hprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn, role_name


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """Retry fn() while SageMaker rejects the freshly-created ExecutionRole as not
    yet visible (IAM's write is eventually consistent from another service's read),
    bounded by a deadline rather than a flat sleep. Any other error is not this lag
    and must not be retried away."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_response(fn):
    """Return the code and message of a rejected call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_for_cluster_status(sm, cluster_name, terminal_statuses, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(2)
    return status


def _wait_for_node_presence(sm, cluster_name, logical_id, present, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sm.list_cluster_nodes(ClusterName=cluster_name)
        found = any(
            node.get("NodeLogicalId") == logical_id for node in resp.get("ClusterNodeSummaries", [])
        )
        if found == present:
            return
        time.sleep(2)
    raise AssertionError(f"node {logical_id} presence never reached expected state present={present}")


def _wait_for_node_running(sm, cluster_name, logical_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        node = sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=logical_id)["NodeDetails"]
        status = node.get("InstanceStatus", {}).get("Status")
        if status == "Running":
            return
        if status == "Failure":
            break
        time.sleep(2)
    raise AssertionError(f"node {logical_id} never reached Running (last status {status!r})")


def _delete_cluster(ctx, cluster_name):
    sm = ctx.client("sagemaker")
    # Bounded well inside the harness's ~60s cleanup budget (DEFAULT_CLEANUP_TIMEOUT_S), not the
    # check body's own 1800s provisioning ceiling: a Slurm-orchestrated cluster can legitimately
    # need more than the derived harness ceiling to settle, and waiting that long here would mean
    # this cleanup helper could never reach its own delete_cluster call, silently leaking a
    # cost-accruing cluster.
    try:
        _wait_for_cluster_status(sm, cluster_name, {"InService", "Failed"}, timeout_s=45)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    try:
        sm.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
