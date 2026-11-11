"""cluster-node-add-and-cluster-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-node-add-and-cluster-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a Slurm HyperPod cluster, BatchAddClusterNodes adds a worker that reaches Running,
    BatchDeleteClusterNodes refuses the controller with the exact ValidationException and removes the
    worker, and after DeleteCluster, DescribeCluster and BatchAddClusterNodes fail ResourceNotFound."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx, managed_policy_arns=["arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"])
    cluster_name = ctx.unique_name("sim2real-cluster-")
    controller_group = "controller"
    worker_group = "workers"

    def _create():
        return sm.create_cluster(
            ClusterName=cluster_name,
            InstanceGroups=[
                {
                    "InstanceCount": 1,
                    "InstanceGroupName": controller_group,
                    "InstanceType": "ml.t3.medium",
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                },
                {
                    "InstanceCount": 0,
                    "InstanceGroupName": worker_group,
                    "InstanceType": "ml.t3.medium",
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Compute", "PartitionNames": [worker_group]},
                },
            ],
            Tags=[{"Key": "sim2real", "Value": "cluster-node-add-and-cluster-delete-lifecycle"}],
            Orchestrator={"Slurm": {}},
        )

    cluster_arn = _retry_role_propagation(_create)["ClusterArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_cluster(ClusterName=cluster_name)))

    status = _poll_until(
        lambda: sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=1800,
        interval_s=30,
    )
    assert status == "InService", f"expected ClusterStatus=InService, got {status}"

    described = sm.describe_cluster(ClusterName=cluster_name)
    assert described["ClusterArn"] == cluster_arn
    assert described["NodeProvisioningMode"] == "Continuous", described.get("NodeProvisioningMode")
    assert _group_current_count(described, controller_group) == 1
    assert _group_current_count(described, worker_group) == 0

    added = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": worker_group, "IncrementTargetCountBy": 1}],
    )
    assert added.get("Failed") == [], f"expected no failed node additions, got {added.get('Failed')}"
    assert [s["InstanceGroupName"] for s in added["Successful"]] == [worker_group], added["Successful"]
    worker_logical_id = added["Successful"][0]["NodeLogicalId"]

    worker_instance_id = _poll_until(
        lambda: _node_instance_id(sm, cluster_name, worker_logical_id),
        lambda iid: iid is not None,
        timeout_s=900,
        interval_s=20,
    )
    assert worker_instance_id, f"added worker node {worker_logical_id} never got an InstanceId"
    worker_status = _poll_until(
        lambda: _node_status(sm, cluster_name, worker_logical_id),
        lambda st: st in ("Running", "Failure", "NotFound"),
        timeout_s=1200,
        interval_s=20,
    )
    assert worker_status == "Running", f"expected the added worker to reach Running, got {worker_status}"

    controller_instance_id = _sole_node_instance_id(sm, cluster_name, controller_group)
    delete_code, delete_message = _error_response(
        lambda: sm.batch_delete_cluster_nodes(
            ClusterName=cluster_name, NodeIds=[controller_instance_id]
        )
    )
    assert delete_code == "ValidationException", (
        f"expected BatchDeleteClusterNodes to reject deleting the Slurm controller node "
        f"with ValidationException, got {delete_code}: {delete_message}"
    )
    expected_delete_message = (
        "All provided nodes failed validation. Please ensure the nodes exist, are not part of "
        "the controller group for the Slurm cluster, and are in a removable state."
    )
    assert delete_message == expected_delete_message, (
        f"expected message {expected_delete_message!r}, got {delete_message!r}"
    )
    assert _sole_node_instance_id(sm, cluster_name, controller_group) == controller_instance_id

    deleted = sm.batch_delete_cluster_nodes(ClusterName=cluster_name, NodeIds=[worker_instance_id])
    assert deleted.get("Successful") == [worker_instance_id], deleted
    assert not deleted.get("Failed"), deleted.get("Failed")
    remaining = _poll_until(
        lambda: _instance_ids(sm, cluster_name),
        lambda ids: worker_instance_id not in ids,
        timeout_s=900,
        interval_s=20,
    )
    assert worker_instance_id not in remaining, (
        f"deleted worker {worker_instance_id} still listed by ListClusterNodes: {remaining}"
    )
    assert controller_instance_id in remaining, remaining

    sm.delete_cluster(ClusterName=cluster_name)

    _poll_until(
        lambda: _cluster_describable(sm, cluster_name),
        lambda describable: not describable,
        timeout_s=1200,
        interval_s=20,
    )
    expected_not_found = f"Cluster with name {cluster_name} not found"
    code, message = _error_response(lambda: sm.describe_cluster(ClusterName=cluster_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    assert message == expected_not_found, f"expected message {expected_not_found!r}, got {message!r}"

    mutate_code, mutate_message = _error_response(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=cluster_name,
            NodesToAdd=[{"InstanceGroupName": worker_group, "IncrementTargetCountBy": 1}],
        )
    )
    assert mutate_code == "ResourceNotFound", (
        f"expected a mutation against the deleted cluster to fail ResourceNotFound, got {mutate_code}"
    )
    assert mutate_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {mutate_message!r}"
    )


def _error_response(fn):
    """Return the code and message of a rejected call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _cluster_describable(sm, cluster_name):
    try:
        sm.describe_cluster(ClusterName=cluster_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFound":
            return False
        raise
    return True


def _group_current_count(described, group_name):
    for group in described["InstanceGroups"]:
        if group["InstanceGroupName"] == group_name:
            return group["CurrentCount"]
    raise AssertionError(f"instance group {group_name!r} missing from DescribeCluster")


def _node_instance_id(sm, cluster_name, logical_id):
    details = sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=logical_id)["NodeDetails"]
    return details.get("InstanceId") or None


def _node_status(sm, cluster_name, logical_id):
    details = sm.describe_cluster_node(ClusterName=cluster_name, NodeLogicalId=logical_id)["NodeDetails"]
    return details["InstanceStatus"]["Status"]


def _instance_ids(sm, cluster_name):
    nodes = sm.list_cluster_nodes(ClusterName=cluster_name).get("ClusterNodeSummaries", [])
    return {n.get("InstanceId") for n in nodes}


def _sole_node_instance_id(sm, cluster_name: str, group_name: str) -> str:
    page = sm.list_cluster_nodes(ClusterName=cluster_name, InstanceGroupNameContains=group_name)
    nodes = page.get("ClusterNodeSummaries", [])
    assert len(nodes) == 1, f"expected exactly one node in {group_name!r}, got {nodes}"
    instance_id = nodes[0].get("InstanceId")
    assert instance_id, f"ListClusterNodes did not return an InstanceId: {nodes[0]}"
    return instance_id


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
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


def _create_sagemaker_role(ctx, managed_policy_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "cluster-node-add-and-cluster-delete-lifecycle"}],
    )
    role_arn = role["Role"]["Arn"]
    attached = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)

    def _cleanup():
        for policy_arn in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
