"""access-entry-kubernetes-groups-order-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-entry-kubernetes-groups-order-preserved"
GROUP = "data-plane"
SERVICES = ["eks"]

_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccessEntry returns kubernetesGroups in the exact order and spelling given to
    CreateAccessEntry (no dedup, reorder or sort), RBAC punctuation included."""
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    cluster_name, _version = _create_active_cluster(ctx)

    principal_name = ctx.unique_name("sim2real-eks-principal-")
    principal_arn = iam.create_role(
        RoleName=principal_name,
        AssumeRolePolicyDocument=_iam_trust_policy("ec2.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_role(ctx, principal_name))

    groups = ["z-team:zeta.alpha", "a-grp:alpha_beta.01", "m-admins:system.masters"]
    _retry_while_role_propagates(
        ctx,
        lambda: eks.create_access_entry(
            clusterName=cluster_name,
            principalArn=principal_arn,
            kubernetesGroups=groups,
            tags={"sim2real": "1"},
        ),
        "create_access_entry",
        total_s=60.0,
    )
    ctx.on_cleanup(lambda: _best_effort_delete_access_entry(ctx, cluster_name, principal_arn))

    described = eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)["accessEntry"]
    assert described["kubernetesGroups"] == groups, (
        f"kubernetesGroups order/values not preserved: expected {groups}, got {described['kubernetesGroups']}"
    )

    described_again = eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)[
        "accessEntry"
    ]
    assert described_again["kubernetesGroups"] == groups, (
        f"kubernetesGroups changed on a second independent read: expected {groups}, "
        f"got {described_again['kubernetesGroups']}"
    )


# ===== helpers =====


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


def _default_vpc_subnets(ctx) -> list[str]:
    """Two-or-more subnets in distinct, EKS-supported AZs, preferring the shared network
    but falling back to any VPC's subnets (a freshly provisioned account may have no
    shared network) - grouped by VPC so the fallback never mixes subnets across VPCs,
    which EKS would reject.
    """
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_vpc: dict[str, dict[str, str]] = {}
    for s in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = s["AvailabilityZone"]
        if s["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_vpc.setdefault(s["VpcId"], {}).setdefault(az, s["SubnetId"])
    by_az = max(by_vpc.values(), key=len, default={})
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs in one VPC, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:3]


def _create_cluster_with_retry(ctx, name: str, role_arn: str, subnet_ids: list[str], version: str | None = None):
    eks = ctx.client("eks")
    kwargs: dict[str, Any] = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        # CreateAccessEntry requires the cluster's authentication mode to include the
        # EKS API (not just the legacy aws-auth ConfigMap).
        accessConfig={"authenticationMode": "API"},
        tags={"sim2real": "1"},
    )
    if version:
        kwargs["version"] = version
    return _retry_while_role_propagates(ctx, lambda: eks.create_cluster(**kwargs), "create_cluster", total_s=80.0)


def _retry_while_role_propagates(ctx, call, what, total_s):
    """Retry call every 2 s while EKS rejects a brand-new IAM role that has not propagated yet,
    up to total_s, capped by the run's remaining time."""
    deadline = time.monotonic() + total_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} kept failing (likely IAM propagation lag): {exc}") from exc
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


def _best_effort_delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_access_entry(ctx, cluster_name: str, principal_arn: str) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_access_entry(clusterName=cluster_name, principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
