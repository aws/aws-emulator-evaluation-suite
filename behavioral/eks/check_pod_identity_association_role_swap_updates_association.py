"""pod-identity-association-role-swap-updates-association."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-role-swap-updates-association"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation changing the target IAM role is immediately reflected
    in subsequent DescribePodIdentityAssociation calls."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    _install_pod_identity_agent(ctx, cluster_name)

    role_a = _pod_identity_role(ctx)
    role_b = _pod_identity_role(ctx)
    namespace = "default"
    service_account = ctx.unique_name("podid-sa-").lower().replace("_", "-")

    created = _create_association_when_role_is_visible(
        eks, cluster_name, namespace, service_account, role_a
    )["association"]
    assoc_id = created["associationId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: eks.delete_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)
        )
    )
    assert created["roleArn"] == role_a, f"expected roleArn {role_a}, got {created['roleArn']}"

    before = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)[
        "association"
    ]
    assert before["roleArn"] == role_a, f"expected roleArn {role_a}, got {before['roleArn']}"

    eks.update_pod_identity_association(clusterName=cluster_name, associationId=assoc_id, roleArn=role_b)

    after = _poll_until(
        lambda: eks.describe_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)[
            "association"
        ],
        lambda a: a["roleArn"] == role_b,
        timeout_s=60,
        interval_s=3,
    )
    assert after["roleArn"] == role_b, f"expected roleArn {role_b} after swap, got {after['roleArn']}"
    assert after["roleArn"] != role_a, "the prior role is still bound after the swap"

    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)
    not_found = f"No service account role association found for ID: {assoc_id}"
    try:
        eks.describe_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)
        raise AssertionError("describe_pod_identity_association still finds the association after delete")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = err.response["Error"]["Message"]
        assert message == not_found, message
    try:
        eks.update_pod_identity_association(clusterName=cluster_name, associationId=assoc_id, roleArn=role_a)
        raise AssertionError("update_pod_identity_association succeeded against a deleted association")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = err.response["Error"]["Message"]
        assert message == not_found, message


# ===== helpers =====
def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _pod_identity_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-podid-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_association_when_role_is_visible(
    eks, cluster_name, namespace, service_account, role_arn, timeout_s=60.0, interval_s=5.0
):
    """CreatePodIdentityAssociation validates roleArn synchronously against IAM, and a role created
    seconds earlier is not yet visible to it. IAM exposes no condition to poll, so the bounded retry
    at first use of the identity is the correct handling; exhausting it FAILS."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.create_pod_identity_association(
                clusterName=cluster_name,
                namespace=namespace,
                serviceAccount=service_account,
                roleArn=role_arn,
                tags={"sim2real-check": CHECK},
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _install_pod_identity_agent(ctx, cluster_name):
    eks = ctx.client("eks")
    eks.create_addon(
        clusterName=cluster_name,
        addonName="eks-pod-identity-agent",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: eks.delete_addon(clusterName=cluster_name, addonName="eks-pod-identity-agent")
        )
    )
    _poll_until(
        lambda: eks.describe_addon(clusterName=cluster_name, addonName="eks-pod-identity-agent")["addon"][
            "status"
        ],
        lambda s: s in ("ACTIVE", "DEGRADED", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=10,
    )


def _iam_role_for_eks_cluster(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _default_vpc_subnet_ids(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to create an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in >=2 AZs, required to create an EKS cluster")
    return list(by_az.values())


def _create_cluster_when_role_is_visible(
    eks, name, role_arn, subnet_ids, authentication_mode, timeout_s=120.0, interval_s=10.0
):
    """CreateCluster validates roleArn synchronously against IAM, and a role created seconds
    earlier is not yet visible to it. IAM exposes no condition to poll, so the bounded retry at
    first use of the identity is the correct handling; exhausting it FAILS."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                accessConfig={"authenticationMode": authentication_mode},
                tags={"sim2real-check": CHECK},
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_active_cluster(ctx, authentication_mode="API"):
    eks = ctx.client("eks")
    role_arn = _iam_role_for_eks_cluster(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx)
    name = ctx.unique_name("sim2real-eks-")
    _create_cluster_when_role_is_visible(eks, name, role_arn, subnet_ids, authentication_mode)

    def _cleanup():
        _ignore_not_found(lambda: eks.delete_cluster(name=name))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"cluster {name} was not deleted within 600s")

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED state during creation")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not become ACTIVE within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
