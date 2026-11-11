"""e2e-cluster-nodegroup-workload-scale-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-cluster-nodegroup-workload-scale-teardown"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create cluster + nodegroup, scale the nodegroup via UpdateNodegroupConfig, observe
    the new scaling config take effect on describe, then tear down and confirm 404s."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)

    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-scale-")
    _create_cluster_via_sdk(ctx, cluster_name, cluster_role_arn, vpc["subnet_ids"])

    nodegroup_name = ctx.unique_name("sim2real-eks-scale-ng-")
    initial_scaling = {"minSize": 1, "maxSize": 2, "desiredSize": 1}
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=vpc["subnet_ids"],
        nodeRole=node_role_arn,
        scalingConfig=initial_scaling,
        instanceTypes=["t3.medium"],
        amiType="AL2023_x86_64_STANDARD",
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _delete_nodegroup_and_wait(ctx, cluster_name, nodegroup_name))
    ng = _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, "ACTIVE", timeout_s=900)
    assert ng["scalingConfig"] == initial_scaling, (
        f"initial scalingConfig not honored: expected {initial_scaling!r}, got {ng['scalingConfig']!r}"
    )

    new_scaling = {"minSize": 2, "maxSize": 4, "desiredSize": 2}
    update_id = eks.update_nodegroup_config(
        clusterName=cluster_name, nodegroupName=nodegroup_name, scalingConfig=new_scaling
    )["update"]["id"]
    _wait_update_successful(ctx, cluster_name, update_id, nodegroup_name=nodegroup_name, timeout_s=600)

    ng_after = _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, "ACTIVE", timeout_s=600)
    assert ng_after["scalingConfig"] == new_scaling, (
        f"scalingConfig did not converge to the requested config: {ng_after['scalingConfig']!r}"
    )

    # Explicit teardown, then assert the resources are truly gone (not just requested).
    eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s=600)

    eks.delete_cluster(name=cluster_name)
    _wait_cluster_deleted(ctx, cluster_name, timeout_s=600)

    code = msg = None
    try:
        eks.describe_cluster(name=cluster_name)
    except Exception as exc:  # noqa: BLE001
        code = exc.response["Error"]["Code"]
        msg = exc.response["Error"].get("Message")
    assert code == "ResourceNotFoundException", (
        f"describe_cluster on a deleted cluster should be ResourceNotFoundException, got {code!r}"
    )
    expected = f"No cluster found for name: {cluster_name}."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not default_vpcs:
        raise AssertionError("no shared network VPC available in this account/region for EKS subnets")
    vpc_id = default_vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    subnet_ids = sorted({s["SubnetId"] for s in subnets})[:3]
    if len(subnet_ids) < 2:
        raise AssertionError(
            f"shared network VPC {vpc_id} does not have enough shared-network subnets for EKS "
            f"(need >=2, found {len(subnet_ids)})"
        )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": None}


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_node_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-node-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]

    def _cleanup():
        try:
            for p in policies:
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    for p in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=p)
    return role_arn


def _create_cluster_via_sdk(ctx, name: str, role_arn: str, subnet_ids: list[str]) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_status(ctx, name, "ACTIVE", timeout_s=1200)


def _wait_cluster_status(ctx, name: str, target: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        last_status = cluster["status"]
        if last_status == target:
            return cluster
        if last_status in ("FAILED",):
            raise AssertionError(f"cluster {name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        _delete_eks_cluster_retrying(eks, name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    _wait_cluster_deleted(ctx, name, timeout_s=timeout_s, interval_s=interval_s)


def _wait_cluster_deleted(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _wait_nodegroup_status(ctx, cluster_name: str, nodegroup_name: str, target: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
        last_status = ng["status"]
        if last_status == target:
            return ng
        if last_status in ("CREATE_FAILED", "DELETE_FAILED"):
            raise AssertionError(f"nodegroup {nodegroup_name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_nodegroup_and_wait(ctx, cluster_name: str, nodegroup_name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s=timeout_s, interval_s=interval_s)


def _wait_nodegroup_deleted(ctx, cluster_name: str, nodegroup_name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} was not deleted within {timeout_s}s")


def _wait_update_successful(ctx, cluster_name: str, update_id: str, nodegroup_name: str | None = None, addon_name: str | None = None, timeout_s: float = 600.0, interval_s: float = 10.0) -> dict:
    eks = ctx.client("eks")
    kwargs = {"name": cluster_name, "updateId": update_id}
    if nodegroup_name:
        kwargs["nodegroupName"] = nodegroup_name
    if addon_name:
        kwargs["addonName"] = addon_name
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        update = eks.describe_update(**kwargs)["update"]
        last_status = update["status"]
        if last_status == "Successful":
            return update
        if last_status == "Failed":
            raise AssertionError(f"update {update_id} failed: {update.get('errors')}")
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} did not reach Successful within {timeout_s}s (last={last_status})")


def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
