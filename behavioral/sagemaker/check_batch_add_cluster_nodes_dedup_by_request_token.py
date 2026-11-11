"""batch-add-cluster-nodes-dedup-by-request-token."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-add-cluster-nodes-dedup-by-request-token"
GROUP = "ordering"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying BatchAddClusterNodes with the same ClientToken and NodesToAdd returns the same
    NodeLogicalIds and advances TargetCount by one add, not two; a nonexistent ClusterName is
    rejected with ResourceNotFound without touching the real cluster's instance groups."""
    sm = ctx.client("sagemaker")
    # The smallest real cluster CreateCluster accepts: one Slurm Controller instance group.
    cluster_name = _provision_slurm_cluster(ctx, "controller")

    described = sm.describe_cluster(ClusterName=cluster_name)
    instance_groups = described.get("InstanceGroups", [])
    if not instance_groups:
        raise AssertionError(
            f"cluster {cluster_name} has no instance groups to add nodes to; cannot exercise "
            "BatchAddClusterNodes idempotency without one."
        )
    instance_group_name = instance_groups[0]["InstanceGroupName"]
    target_count_before = instance_groups[0].get("TargetCount")

    # break exactly one thing: a ClusterName that does not exist at all (not merely an
    # instance group within a real cluster)
    bogus_cluster_name = ctx.unique_name("sim2real-nocluster-")
    code, message = _error(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=bogus_cluster_name,
            NodesToAdd=[{"InstanceGroupName": "any", "IncrementTargetCountBy": 1}],
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = f"Cluster with name {bogus_cluster_name} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the real cluster's instance group is untouched by the bogus-cluster call
    unaffected = sm.describe_cluster(ClusterName=cluster_name)["InstanceGroups"][0]
    assert unaffected["TargetCount"] == target_count_before

    # positive control + idempotency: add one node to the real instance group, then retry
    # the identical request (same ClientToken, same NodesToAdd)
    token = ctx.unique_name("sim2real-token-")
    nodes_to_add = [{"InstanceGroupName": instance_group_name, "IncrementTargetCountBy": 1}]

    resp1 = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name, ClientToken=token, NodesToAdd=nodes_to_add
    )
    successful_1 = resp1.get("Successful", [])
    if not successful_1:
        raise AssertionError(
            f"instance group {instance_group_name} on cluster {cluster_name} has no spare "
            f"target capacity right now (Failed={resp1.get('Failed')}); cannot observe "
            "NodeLogicalId dedup without at least one successfully queued node addition."
        )
    node_ids_1 = sorted(n["NodeLogicalId"] for n in successful_1)

    resp2 = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name, ClientToken=token, NodesToAdd=nodes_to_add
    )
    ctx.on_cleanup(lambda: _best_effort_delete_nodes(sm, cluster_name, node_ids_1))
    node_ids_2 = sorted(n["NodeLogicalId"] for n in resp2.get("Successful", []))

    assert node_ids_2 == node_ids_1, (
        f"retrying BatchAddClusterNodes with the same ClientToken produced a different set "
        f"of NodeLogicalIds: first={node_ids_1} second={node_ids_2}"
    )

    updated = _poll_until(
        lambda: sm.describe_cluster(ClusterName=cluster_name)["InstanceGroups"][0],
        lambda ig: ig["TargetCount"] == target_count_before + len(node_ids_1),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert updated["TargetCount"] == target_count_before + len(node_ids_1), (
        "instance group TargetCount advanced by more than the single deduplicated add "
        f"(before={target_count_before}, after={updated['TargetCount']}, "
        f"added_nodes={len(node_ids_1)})"
    )


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _best_effort_delete_nodes(sm, cluster_name, node_logical_ids):
    try:
        sm.batch_delete_cluster_nodes(ClusterName=cluster_name, NodeLogicalIds=node_logical_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _provision_slurm_cluster(ctx, group_name: str) -> str:
    """The smallest real cluster CreateCluster accepts: one Slurm Controller instance group in
    the default VPC (or a VPC the check creates), waited to InService."""
    sm = ctx.client("sagemaker")
    role_arn = _create_role(ctx)
    subnet_ids, sg_id = _default_vpc_network(ctx)
    cluster_name = ctx.unique_name("sim2real-sm-cl-")

    def _create():
        return sm.create_cluster(
            ClusterName=cluster_name,
            InstanceGroups=[
                {
                    "InstanceGroupName": group_name,
                    "InstanceType": "ml.c5.xlarge",
                    "InstanceCount": 1,
                    "ExecutionRole": role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                }
            ],
            VpcConfig={"SecurityGroupIds": [sg_id], "Subnets": subnet_ids},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _cleanup_cluster(ctx, cluster_name))
    _wait_cluster_status(ctx, cluster_name, "InService", timeout_s=1200)
    return cluster_name


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
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
    # Teardowns run LIFO: the delete is registered first so the policy detach runs before it.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _default_vpc_network(ctx: Any) -> tuple[list[str], str]:
    """Two subnets and the default security group of the shared network; an account without a
    shared network gets a VPC with two subnets that this check creates and deletes."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnet_ids = [
            s["SubnetId"]
            for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        ][:2]
    else:
        vpc_id, subnet_ids = _create_vpc_with_subnets(ctx, ec2)
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_ids, sg_id


def _create_vpc_with_subnets(ctx: Any, ec2: Any) -> tuple[str, list[str]]:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.195.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.195.{i}.0/24",
            AvailabilityZone=azs[i % len(azs)]["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _delete_retrying(fn, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    """Retry a network delete while HyperPod's ENIs leave the subnet (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_cluster_status(ctx: Any, cluster_name: str, want: str, timeout_s: float, interval_s: float = 20.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = sm.describe_cluster(ClusterName=cluster_name)
        if described["ClusterStatus"] == want:
            return
        if described["ClusterStatus"] == "Failed":
            raise AssertionError(f"HyperPod cluster entered Failed: {described.get('FailureMessage')!r}")
        time.sleep(interval_s)
    raise AssertionError(f"HyperPod cluster did not reach {want} within {timeout_s}s")


def _cleanup_cluster(ctx: Any, cluster_name: str) -> None:
    _delete_cluster_and_wait(ctx.client("sagemaker"), cluster_name)


def _delete_cluster_and_wait(sm, cluster_name, timeout_s=600.0, interval_s=15.0):
    """Delete the cluster and wait until it is gone: HyperPod tears down the cluster's ENIs in
    the VPC with the execution role, so the role must outlive the deletion."""
    try:
        sm.delete_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
