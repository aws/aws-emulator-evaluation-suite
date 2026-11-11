"""batch-delete-cluster-nodes-partial-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-delete-cluster-nodes-partial-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteClusterNodes on a batch mixing a real node id with a non-existent, well-formed one
    reports InstanceIdNotFound with the exact message for the bad id in `Failed` while the real id
    succeeds in `Successful`: a single call is its own positive/negative control pair.
    """
    sm = ctx.client("sagemaker")
    role_arn = _create_execution_role(ctx)

    cluster_name = ctx.unique_name("sim2real-cluster-")
    instance_group_name = "worker"

    def _create():
        return sm.create_cluster(
            ClusterName=cluster_name,
            Orchestrator={"Slurm": {}},
            InstanceGroups=[
                {
                    "InstanceGroupName": "controller",
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                },
                {
                    "InstanceGroupName": instance_group_name,
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 0,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Compute", "PartitionNames": [instance_group_name]},
                },
            ],
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _delete_cluster_when_idle(sm, cluster_name))

    _poll_until(
        lambda: sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"],
        lambda status: status == "InService",
        timeout_s=1200,
        interval_s=20,
        description="cluster to become InService",
    )

    add_resp = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": instance_group_name, "IncrementTargetCountBy": 1}],
    )
    assert not add_resp.get("Failed"), add_resp.get("Failed")
    node_logical_id = add_resp["Successful"][0]["NodeLogicalId"]

    instance_id = _poll_until(
        lambda: sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=node_logical_id)[
            "NodeDetails"
        ].get("InstanceId"),
        lambda iid: bool(iid),
        timeout_s=900,
        interval_s=20,
        description="added node to be assigned a real InstanceId",
    )
    _poll_until(
        lambda: sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=node_logical_id)[
            "NodeDetails"
        ]["InstanceStatus"]["Status"],
        lambda status: status == "Running",
        timeout_s=1200,
        interval_s=20,
        description="added node to reach Running",
    )

    # A well-formed (17 hex digit) instance id that names no node in this cluster.
    bogus_instance_id = "i-" + "0" * 8 + "deadbeef0"
    delete_resp = sm.batch_delete_cluster_nodes(
        ClusterName=cluster_name, NodeIds=[instance_id, bogus_instance_id]
    )

    successful = delete_resp.get("Successful", [])
    failed = {entry["NodeId"]: entry for entry in delete_resp.get("Failed", [])}

    assert successful == [instance_id], successful
    assert list(failed) == [bogus_instance_id], failed
    assert failed[bogus_instance_id]["Code"] == "InstanceIdNotFound", failed
    expected_item_message = "Node does not exist in the given cluster."
    assert failed[bogus_instance_id].get("Message") == expected_item_message, failed

    # Independent terminal read at the destination: the deleted node is actually gone,
    # not just reported gone by the mutating call's own response.
    _poll_until(
        lambda: _node_describable(sm, cluster_name, node_logical_id),
        lambda describable: not describable,
        timeout_s=900,
        interval_s=15,
        description="deleted node to stop resolving via DescribeClusterNode",
    )
    deletion_code, deletion_message = _error_response(
        lambda: sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=node_logical_id)
    )
    assert deletion_code == "ResourceNotFound", deletion_code
    expected_deletion_message = "Specified cluster node not found"
    assert deletion_message == expected_deletion_message, (
        f"expected message {expected_deletion_message!r}, got {deletion_message!r}"
    )


# ===== helpers =====


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cluster-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    policy_arns = [
        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        "arn:aws:iam::aws:policy/AmazonSageMakerClusterInstanceRolePolicy",
    ]
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role() -> None:
        for policy_arn in policy_arns:
            _safe_call(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
        _safe_call(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

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


def _delete_cluster_when_idle(sm, cluster_name: str, timeout_s: float = 900, interval_s: float = 2) -> None:
    """Delete the cluster, retrying ConflictException while it finishes an ongoing change."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_cluster(ClusterName=cluster_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} (last observed: {last!r})")


def _node_describable(sm, cluster_name: str, node_logical_id: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=node_logical_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return False
        raise
    return True


def _error_response(fn):
    """Return the code and message of a rejected call; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
