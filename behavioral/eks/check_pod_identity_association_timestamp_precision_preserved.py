"""pod-identity-association-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pod-identity-association-timestamp-precision-preserved"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """createdAt/modifiedAt on a pod identity association are persisted exactly (not re-derived,
    truncated or re-quantized) across repeated describes separated by real elapsed time."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    name = cluster["name"]

    role_arn = _create_pod_identity_role(ctx)
    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-")

    created = _until_role_propagates(ctx, lambda: eks.create_pod_identity_association(
        clusterName=name,
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=role_arn,
    ))["association"]
    association_id = created["associationId"]
    ctx.on_cleanup(lambda: eks.delete_pod_identity_association(clusterName=name, associationId=association_id))

    created_at = created["createdAt"]
    modified_at = created["modifiedAt"]
    assert created_at.tzinfo is not None, "createdAt must be a timezone-aware timestamp"
    created_at_microsecond = created_at.microsecond

    for _ in range(2):
        time.sleep(3)
        described = eks.describe_pod_identity_association(clusterName=name, associationId=association_id)[
            "association"
        ]
        assert described["createdAt"] == created_at, (
            f"createdAt drifted across repeated describes: {described['createdAt']!r} != {created_at!r}"
        )
        assert described["createdAt"].microsecond == created_at_microsecond, (
            "createdAt sub-second precision changed across repeated describes"
        )
        assert described["modifiedAt"] == modified_at, (
            f"modifiedAt drifted with no update performed: {described['modifiedAt']!r} != {modified_at!r}"
        )


def _get_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision the EKS cluster prerequisite subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 availability zones for an EKS cluster")
    return list(by_az.values())[:3]


def _until_role_propagates(ctx, call):
    """call(), retried every 2 s while EKS answers InvalidParameterException for a role IAM has not propagated."""
    left = ctx.time_left()
    deadline = time.monotonic() + min(120.0, 120.0 if left is None else left)
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
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
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _create_pod_identity_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-pia-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _wait_for_cluster_active(ctx, name, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


def _delete_cluster_safe(ctx, name):
    eks = ctx.client("eks")
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = eks.describe_cluster(name=name)["cluster"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("CREATING", "UPDATING", "DELETING"):
            break
        time.sleep(15)
    _delete_eks_cluster_retrying(eks, name)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})
    kwargs.update(extra_kwargs)
    _until_role_propagates(ctx, lambda: eks.create_cluster(**kwargs))
    ctx.on_cleanup(lambda: _delete_cluster_safe(ctx, name))
    return _wait_for_cluster_active(ctx, name)


def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
