"""pod-identity-association-update-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-update-lifecycle"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation mutates roleArn/targetRoleArn in place while
    associationId, namespace, serviceAccount and createdAt are preserved."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    role_a = _create_pod_identity_role(ctx, "a")
    role_b = _create_pod_identity_role(ctx, "b")
    target_role = _create_pod_identity_role(ctx, "target")

    namespace = "default"
    service_account = ctx.unique_name("svc-acct-").replace("_", "-")[:63]

    created = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=role_a,
    )["association"]
    association_id = created["associationId"]
    created_at = created["createdAt"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    )
    assert created["roleArn"] == role_a
    assert "targetRoleArn" not in created or created.get("targetRoleArn") is None

    eks.update_pod_identity_association(
        clusterName=cluster_name,
        associationId=association_id,
        roleArn=role_b,
        targetRoleArn=target_role,
    )

    updated = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)[
        "association"
    ]
    assert updated["associationId"] == association_id
    assert updated["namespace"] == namespace
    assert updated["serviceAccount"] == service_account
    assert updated["createdAt"] == created_at
    assert updated["roleArn"] == role_b
    assert updated["targetRoleArn"] == target_role
    assert updated["modifiedAt"] >= created_at


# ===== helpers =====
def _error_code(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _default_vpc_subnets(ctx, min_subnets: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < min_subnets:
        raise AssertionError("shared network lacks subnets in enough distinct AZs for an EKS cluster")
    return subnet_ids[:3]


def _create_eks_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_active_cluster(ctx, version: str | None = None) -> str:
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    role_arn = _create_eks_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": {"subnetIds": subnet_ids},
        "tags": {"sim2real:managed": "true"},
    }
    if version:
        kwargs["version"] = version

    # A role just created by IAM can take a few seconds to propagate before EKS can assume it;
    # retry the create on that specific, transient rejection rather than a blind pre-sleep.
    create_deadline = time.monotonic() + 80
    left = ctx.time_left()
    if left is not None:
        create_deadline = min(create_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            transient = exc.response["Error"]["Code"] in ("InvalidParameterException", "ClientException")
            if not transient or time.monotonic() >= create_deadline:
                raise
            time.sleep(2)

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name


def _create_pod_identity_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-podid-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _cleanup() -> None:
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
