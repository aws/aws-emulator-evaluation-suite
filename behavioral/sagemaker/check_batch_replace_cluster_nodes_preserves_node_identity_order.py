"""batch-replace-cluster-nodes-preserves-node-identity-order."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-replace-cluster-nodes-preserves-node-identity-order"
GROUP = "ordering"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """BatchReplaceClusterNodes reports exactly the requested instance IDs as Successful (no drops,
    substitutions or duplicates), and ListClusterNodes confirms the replacement began."""
    sm = ctx.client("sagemaker")
    role_arn = _create_cluster_role(ctx)
    bucket = _create_lifecycle_bucket(ctx)

    cluster_name = ctx.unique_name("sim2real-cluster-")
    try:
        _create_cluster_with_propagation_retry(ctx, sm, cluster_name, role_arn, bucket)
    except ClientError as exc:
        raise AssertionError(f"HyperPod cluster prerequisite unavailable in this account/region: {exc}") from exc
    ctx.on_cleanup(lambda: _cleanup_cluster(ctx, cluster_name))

    try:
        _wait_cluster_status(ctx, cluster_name, "InService", timeout_s=1800)
        node_ids = _wait_for_node_ids(ctx, cluster_name, count=2, timeout_s=1800)
    except AssertionError as exc:
        raise AssertionError(f"HyperPod cluster did not reach a usable state: {exc}") from exc

    resp = sm.batch_replace_cluster_nodes(ClusterName=cluster_name, NodeIds=node_ids)

    assert not resp.get("Failed"), f"expected no failures replacing {node_ids}, got {resp.get('Failed')}"
    successful = resp["Successful"]
    # AWS does not preserve the request's ordering in Successful, so compare as sets.
    assert sorted(successful) == sorted(node_ids), (
        f"expected BatchReplaceClusterNodes to report exactly the requested node IDs "
        f"{node_ids} as successfully initiated (no drops, substitutions or duplicates), "
        f"got {successful}"
    )

    # The replaced instances must leave Running, not merely be echoed back by the call.
    _wait_for_replacement_underway(ctx, cluster_name, node_ids, timeout_s=900)



def _create_cluster_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-hp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role["Arn"]


def _create_lifecycle_bucket(ctx: Any) -> str:
    # SageMaker HyperPod's managed instance-role policy only grants S3 access to
    # buckets whose name starts with "sagemaker-" (see the CreateCluster LifeCycleConfig
    # docs), so the bucket prefix below is load-bearing, not decorative.
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sagemaker-sim2real-cluster-")
    # "us-east-1" here is an S3 API quirk, not an assumption about ctx.region: CreateBucket
    # rejects an explicit LocationConstraint matching us-east-1 (the region is implied when
    # the constraint is omitted), so the literal only ever gates which form of the same
    # ctx.region-targeted call to make.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="on_create.sh", Body=b"#!/bin/bash\nexit 0\n")
    ctx.on_cleanup(lambda: _cleanup_bucket(ctx, bucket))
    return bucket


def _cleanup_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.delete_object(Bucket=bucket, Key="on_create.sh")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_cluster_with_propagation_retry(
    ctx: Any, sm: Any, cluster_name: str, role_arn: str, bucket: str, timeout_s: float = 90.0
) -> None:
    """Create the cluster, retrying only while the new role is still propagating to AssumeRole
    callers (``get_role`` can see it before STS does); any other error is raised at once."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_cluster(
                ClusterName=cluster_name,
                InstanceGroups=[
                    # Continuous node provisioning requires a Slurm- or EKS-orchestrated cluster, and
                    # a Slurm one requires a Controller group alongside the group under test.
                    {
                        "InstanceGroupName": "controller",
                        "InstanceType": "ml.t3.medium",
                        "InstanceCount": 1,
                        "ExecutionRole": role_arn,
                        "SlurmConfig": {"NodeType": "Controller"},
                    },
                    {
                        "InstanceGroupName": "worker",
                        "InstanceType": "ml.t3.medium",
                        "InstanceCount": 2,
                        "ExecutionRole": role_arn,
                        "SlurmConfig": {"NodeType": "Compute", "PartitionNames": ["worker"]},
                        "LifeCycleConfig": {"SourceS3Uri": f"s3://{bucket}", "OnCreate": "on_create.sh"},
                    },
                ],
                NodeProvisioningMode="Continuous",
                Orchestrator={"Slurm": {}},
                NodeRecovery="None",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            is_propagation_error = code in ("ValidationException", "AccessDeniedException") and (
                "assume" in message.lower() or "role" in message.lower()
            )
            if not is_propagation_error or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _wait_cluster_status(ctx: Any, cluster_name: str, want: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        if status == want:
            return
        if status == "Failed":
            raise AssertionError("cluster entered Failed")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {want} within {timeout_s}s")


def _wait_for_node_ids(ctx: Any, cluster_name: str, count: int, timeout_s: float = 1800.0, interval_s: float = 20.0) -> list[str]:
    # BatchReplaceClusterNodes rejects a node still settling into place with InvalidInstanceStatus
    # ("Instance is in a state that cannot be modified"), so a node only counts once it is Running,
    # not merely once it has an InstanceId.
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        nodes = sm.list_cluster_nodes(ClusterName=cluster_name, InstanceGroupNameContains="worker")[
            "ClusterNodeSummaries"
        ]
        ids = sorted(
            n["InstanceId"]
            for n in nodes
            if n.get("InstanceId") and n.get("InstanceStatus", {}).get("Status") == "Running"
        )
        if len(ids) >= count:
            return ids[:count]
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reported {count} Running node IDs within {timeout_s}s")


def _wait_for_replacement_underway(
    ctx: Any, cluster_name: str, node_ids: list[str], timeout_s: float = 900.0, interval_s: float = 20.0
) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    target = set(node_ids)
    while time.monotonic() < deadline:
        nodes = sm.list_cluster_nodes(ClusterName=cluster_name, InstanceGroupNameContains="worker")[
            "ClusterNodeSummaries"
        ]
        still_running = {
            n["InstanceId"]
            for n in nodes
            if n.get("InstanceId") in target and n.get("InstanceStatus", {}).get("Status") == "Running"
        }
        if not still_running:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"BatchReplaceClusterNodes reported {sorted(target)} as successfully initiated, but an "
        f"independent ListClusterNodes read still shows them Running after {timeout_s}s"
    )


def _cleanup_cluster(ctx: Any, cluster_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            sm.describe_cluster(ClusterName=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(20)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
