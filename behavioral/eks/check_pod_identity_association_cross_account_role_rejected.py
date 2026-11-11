"""pod-identity-association-cross-account-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-cross-account-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation to a roleArn the caller cannot pass (a role in an account it
    does not control, with no trust for EKS Pod Identity) fails AccessDeniedException and leaves the
    roleArn unchanged, while updating to a second valid role succeeds."""
    eks = ctx.client("eks")
    sts = ctx.client("sts")
    cluster = _create_active_cluster(ctx)

    role_arn_1 = _create_pod_identity_role(ctx, "a")
    service_account = ctx.unique_name("sa-")
    assoc = eks.create_pod_identity_association(
        clusterName=cluster,
        namespace="default",
        serviceAccount=service_account,
        roleArn=role_arn_1,
    )["association"]
    assoc_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(clusterName=cluster, associationId=assoc_id)
    )

    # Build a role ARN in an account the caller definitely does not control, with
    # no trust relationship for pods.eks.amazonaws.com -- the caller cannot pass it.
    own_account = sts.get_caller_identity()["Account"]
    bogus_account = "111111111111" if own_account != "111111111111" else "222222222222"
    bogus_role_arn = f"arn:aws:iam::{bogus_account}:role/{ctx.unique_name('no-trust-')}"

    code, msg = _error_code(
        lambda: eks.update_pod_identity_association(
            clusterName=cluster, associationId=assoc_id, roleArn=bogus_role_arn
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert msg == "Cross-account pass role is not allowed.", f"unexpected message: {msg!r}"

    # Effect absent: the association still points at the original role.
    unchanged = eks.describe_pod_identity_association(clusterName=cluster, associationId=assoc_id)[
        "association"
    ]
    assert unchanged["roleArn"] == role_arn_1, (
        f"expected roleArn unchanged at {role_arn_1!r} after rejected update, got {unchanged['roleArn']!r}"
    )

    # Positive control: updating to a valid, assumable role succeeds.
    role_arn_2 = _create_pod_identity_role(ctx, "b")
    eks.update_pod_identity_association(
        clusterName=cluster, associationId=assoc_id, roleArn=role_arn_2
    )
    updated = eks.describe_pod_identity_association(clusterName=cluster, associationId=assoc_id)[
        "association"
    ]
    assert updated["roleArn"] == role_arn_2, (
        f"expected roleArn updated to {role_arn_2!r} after valid update, got {updated['roleArn']!r}"
    )


# ===== helpers =====


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _pick_subnets(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "account/region lacks a shared network VPC with subnets in >=2 AZs; cannot "
            "provision a real EKS cluster for this check"
        )
    return list(by_az.values())[:3]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
            )
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


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _pick_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-ekscl-")

    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    retry_deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= retry_deadline:
                raise AssertionError(f"create_cluster never succeeded after IAM propagation retries: {exc}") from exc
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    return cluster_name


def _create_pod_identity_role(ctx, suffix):
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
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )

    def _cleanup():
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
