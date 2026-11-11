"""nodegroup-duplicate-create-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodegroup-duplicate-create-rejected"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateNodegroup for the name of an ACTIVE nodegroup is rejected with ResourceInUseException and
    its exact message, leaving that nodegroup ACTIVE with modifiedAt unchanged, while a distinct name on the
    same cluster becomes ACTIVE and both are listed."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)

    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-dd-")
    _create_cluster_via_sdk(ctx, cluster_name, cluster_role_arn, vpc["subnet_ids"])

    nodegroup_name = ctx.unique_name("sim2real-eks-dd-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=vpc["subnet_ids"],
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.medium"],
        amiType="AL2023_x86_64_STANDARD",
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s=600))
    active = _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, "ACTIVE", timeout_s=900)
    original_modified_at = active["modifiedAt"]

    # A second CreateNodegroup with the SAME name on the SAME cluster must be rejected --
    # the name is already in use by a live (ACTIVE) nodegroup.
    try:
        eks.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
            subnets=vpc["subnet_ids"],
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            instanceTypes=["t3.medium"],
            amiType="AL2023_x86_64_STANDARD",
        )
    except ClientError as exc:
        code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    else:
        raise AssertionError("a duplicate CreateNodegroup for a live nodegroup name SUCCEEDED; expected ResourceInUseException")
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code!r}"
    assert msg == f"NodeGroup already exists with name {nodegroup_name} and cluster name {cluster_name}", (
        f"unexpected message: {msg!r}"
    )

    # Effect absent: the rejected duplicate create did not disturb the existing nodegroup.
    unchanged = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    assert unchanged["status"] == "ACTIVE", f"expected existing nodegroup to remain ACTIVE, got {unchanged['status']!r}"
    assert unchanged["modifiedAt"] == original_modified_at, (
        f"rejected duplicate create must not touch modifiedAt: "
        f"expected {original_modified_at!r}, got {unchanged['modifiedAt']!r}"
    )

    # Positive control: a genuinely distinct name on the same cluster succeeds for real.
    other_name = ctx.unique_name("sim2real-eks-dd-ng2-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=other_name,
        subnets=vpc["subnet_ids"],
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.medium"],
        amiType="AL2023_x86_64_STANDARD",
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _wait_nodegroup_deleted(ctx, cluster_name, other_name, timeout_s=600))
    _wait_nodegroup_status(ctx, cluster_name, other_name, "ACTIVE", timeout_s=900)

    names = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name in names and other_name in names, (
        f"expected both {nodegroup_name!r} and {other_name!r} in ListNodegroups, got {names!r}"
    )


def _retry_delete(fn, attempts: int = 12, delay_s: float = 10.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(delay_s)
    if last_exc is not None:
        raise last_exc


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _wait_nodegroup_deleted(ctx, cluster_name: str, nodegroup_name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise
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
