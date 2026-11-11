"""pod-identity-association-duplicate-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pod-identity-association-duplicate-rejected"
GROUP = "data-plane"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate CreatePodIdentityAssociation (same cluster, namespace, serviceAccount) fails
    ResourceInUseException and leaves exactly one association, while a different serviceAccount
    on the same cluster still succeeds."""
    eks = ctx.client("eks")
    cluster_name, _version = _create_active_cluster(ctx)
    pod_role_arn = _create_pod_role(ctx)

    namespace = "default"
    service_account = ctx.unique_name("svc-acct-").replace("_", "-")

    first = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=pod_role_arn,
    )["association"]
    first_id = first["associationId"]
    ctx.on_cleanup(lambda: _best_effort_delete_association(ctx, cluster_name, first_id))

    code, msg = _error_code(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=pod_role_arn,
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code!r}"
    assert msg == f"Association already exists: {first_id}", f"unexpected message: {msg!r}"

    # effect absent: still exactly one association for this namespace/serviceAccount
    associations = eks.list_pod_identity_associations(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert len(associations) == 1, (
        f"a rejected duplicate association must not create a second entry, found {len(associations)}"
    )
    assert associations[0]["associationId"] == first_id, (
        f"expected the surviving association to be {first_id!r}, got {associations[0]['associationId']!r}"
    )

    # positive control: a different serviceAccount on the same cluster succeeds
    other_service_account = ctx.unique_name("svc-acct-other-").replace("_", "-")
    second = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=other_service_account,
        roleArn=pod_role_arn,
    )["association"]
    ctx.on_cleanup(
        lambda: _best_effort_delete_association(ctx, cluster_name, second["associationId"])
    )
    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=second["associationId"]
    )["association"]
    assert described["serviceAccount"] == other_service_account, (
        f"expected the positive-control association's serviceAccount to be "
        f"{other_service_account!r}, got {described['serviceAccount']!r}"
    )


# ===== helpers =====


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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
        RoleName=name, AssumeRolePolicyDocument=_iam_trust_policy("eks.amazonaws.com")
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


def _create_pod_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-podrole-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "pods.eks.amazonaws.com"},
                        "Action": ["sts:AssumeRole", "sts:TagSession"],
                    }
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_role(ctx, name))
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
    kwargs: dict[str, Any] = dict(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
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


def _best_effort_delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_association(ctx, cluster_name: str, association_id: str) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
