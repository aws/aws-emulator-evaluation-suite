"""nodegroup-scaling-config-invalid-range-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "nodegroup-scaling-config-invalid-range-rejected"
GROUP = "data-plane"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNodegroup with minSize > maxSize is rejected with InvalidParameterException,
    no nodegroup is created for that name, and a nodegroup with a valid scaling range
    on the very same cluster still succeeds (positive control)."""
    eks = ctx.client("eks")
    cluster_name, _version = _create_active_cluster(ctx)
    node_role_arn = _create_node_role(ctx)
    subnet_ids = _default_vpc_subnets(ctx)

    bad_name = ctx.unique_name("sim2real-eks-ng-bad-")
    code, msg = _error_code(
        lambda: eks.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName=bad_name,
            subnets=subnet_ids,
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 5, "maxSize": 2, "desiredSize": 3},
            tags={"sim2real": "1"},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert msg == "minSize can't be greater than desiredSize", f"unexpected message: {msg!r}"

    # effect absent: the rejected nodegroup must not exist
    names = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert bad_name not in names, "a nodegroup rejected for an invalid scaling range must not have been created"

    # positive control: a valid scaling range on the same cluster succeeds
    good_name = ctx.unique_name("sim2real-eks-ng-good-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=good_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 0, "maxSize": 2, "desiredSize": 0},
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(ctx, cluster_name, good_name))
    described = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=good_name)["nodegroup"]
    assert described["scalingConfig"] == {"minSize": 0, "maxSize": 2, "desiredSize": 0}


# ===== helpers =====


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _iam_trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-clusterrole-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_iam_trust_policy("eks.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_node_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-noderole-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_iam_trust_policy("ec2.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]
    for policy_arn in policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        for policy_arn in policies:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host an EKS control plane")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network lacks subnets in >=2 AZs required to create an EKS cluster")
    return subnet_ids[:3]


def _create_cluster_with_retry(ctx, name: str, role_arn: str, subnet_ids: list[str], version: str | None = None):
    eks = ctx.client("eks")
    kwargs: dict[str, Any] = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real": "1"},
    )
    if version:
        kwargs["version"] = version
    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return eks.create_cluster(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"create_cluster kept failing (likely IAM propagation lag): {exc}") from exc
        time.sleep(2)


def _wait_cluster_active(ctx, name: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> str:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster["version"]
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _create_active_cluster(ctx) -> tuple[str, str]:
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _default_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")
    _create_cluster_with_retry(ctx, name, role_arn, subnet_ids)

    def _delete() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            time.sleep(15)

    ctx.on_cleanup(_delete)
    version = _wait_cluster_active(ctx, name)
    return name, version


def _delete_nodegroup(ctx, cluster_name: str, nodegroup_name: str) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            status = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)[
                "nodegroup"
            ]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("CREATING", "UPDATING", "DELETING"):
            break
        time.sleep(15)
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(15)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
