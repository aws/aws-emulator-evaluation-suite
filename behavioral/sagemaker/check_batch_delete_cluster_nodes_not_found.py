"""batch-delete-cluster-nodes-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-cluster-nodes-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteClusterNodes reports an unknown but well-formed EC2 instance id in `NodeIds` as
    InstanceIdNotFound while deleting a real node of the same cluster in the same call, and the
    real node then leaves ListClusterNodes.
    """
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-hyperpod-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        )
        ctx.on_cleanup(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
            )
        )
    except ClientError as exc:
        raise AssertionError(f"could not provision the HyperPod execution IAM role: {exc}") from None

    cluster_name = ctx.unique_name("sim2real-hpcluster-")
    worker_group_name = "worker"

    # CreateCluster requires a Slurm Controller group next to the worker group whose node is deleted.
    def _create():
        return sm.create_cluster(
            ClusterName=cluster_name,
            InstanceGroups=[
                {
                    "InstanceGroupName": "controller",
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                },
                {
                    "InstanceGroupName": worker_group_name,
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Compute"},
                },
            ],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["ClusterArn"]

    try:
        _retry_role_propagation(_create)
    except ClientError as exc:
        raise AssertionError(f"CreateCluster was rejected in this environment: {exc}") from None
    ctx.on_cleanup(lambda: _delete_cluster_ignore(sm, cluster_name))

    valid_instance_id = _wait_for_node_instance_id(sm, cluster_name, worker_group_name, timeout_s=900)
    if valid_instance_id is None:
        raise AssertionError(
            "no EC2 instance ID was assigned to the worker HyperPod node within the timeout; "
            "provide account capacity/VPC prerequisites to close this gap"
        )

    # Real AWS rejects BatchDeleteClusterNodes while the cluster is still Creating ("Please
    # wait for cluster to finish ongoing changes"), so the node having an InstanceId is not
    # by itself enough -- the cluster must actually reach InService first.
    cluster_status = _wait_for_cluster_status(sm, cluster_name, {"InService", "Failed"}, timeout_s=2400)
    if cluster_status != "InService":
        raise AssertionError(
            f"HyperPod cluster did not reach InService within the timeout (last status: {cluster_status!r})"
        )

    bogus_instance_id = "i-" + "f" * 17

    resp = sm.batch_delete_cluster_nodes(
        ClusterName=cluster_name, NodeIds=[valid_instance_id, bogus_instance_id]
    )

    failed_by_id = {f["NodeId"]: f for f in resp.get("Failed", [])}
    bogus_failure = failed_by_id.get(bogus_instance_id)
    assert bogus_failure is not None, f"expected {bogus_instance_id} in Failed, got {resp!r}"
    assert bogus_failure["Code"] == "InstanceIdNotFound", (
        f"expected Failed[{bogus_instance_id}].Code == 'InstanceIdNotFound', got {bogus_failure!r}"
    )
    expected_message = "Node does not exist in the given cluster."
    assert bogus_failure.get("Message") == expected_message, (
        f"expected Failed[{bogus_instance_id}].Message == {expected_message!r}, got {bogus_failure!r}"
    )
    assert valid_instance_id in resp.get("Successful", []), (
        f"expected {valid_instance_id} in Successful, got {resp.get('Successful')!r}"
    )
    assert valid_instance_id not in failed_by_id, (
        f"expected {valid_instance_id} absent from Failed, got {failed_by_id!r}"
    )

    # Effect: the real node actually disappears from the cluster's node list.
    deadline = time.monotonic() + 900
    remaining_ids = set()
    while time.monotonic() < deadline:
        remaining_ids = {
            n["InstanceId"] for n in sm.list_cluster_nodes(ClusterName=cluster_name).get("ClusterNodeSummaries", [])
        }
        if valid_instance_id not in remaining_ids:
            break
        time.sleep(2)
    assert valid_instance_id not in remaining_ids, (
        f"expected {valid_instance_id} gone from ListClusterNodes within 900s, still present: {remaining_ids!r}"
    )


# ===== helpers =====
def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 2.0):
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


def _delete_cluster_ignore(sm, cluster_name: str) -> None:
    try:
        sm.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _wait_for_cluster_status(sm, cluster_name: str, terminal_statuses: set, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    return status


def _wait_for_node_instance_id(sm, cluster_name: str, instance_group_name: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            nodes = sm.list_cluster_nodes(ClusterName=cluster_name).get("ClusterNodeSummaries", [])
        except ClientError:
            nodes = []
        for node in nodes:
            instance_id = node.get("InstanceId")
            if (
                node.get("InstanceGroupName") == instance_group_name
                and instance_id
                and instance_id.startswith("i-")
            ):
                return instance_id
        time.sleep(2)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
