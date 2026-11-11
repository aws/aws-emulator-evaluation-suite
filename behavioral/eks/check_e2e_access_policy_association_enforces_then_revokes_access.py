"""e2e-access-policy-association-enforces-then-revokes-access."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-access-policy-association-enforces-then-revokes-access"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """End-to-end: create an access entry, associate an access policy, confirm
    ListAssociatedAccessPolicies reflects the grant, then disassociate and confirm the
    grant is actually gone (not merely that each call returned 200)."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx, extra_kwargs={"accessConfig": {"authenticationMode": "API_AND_CONFIG_MAP"}})
    principal_arn, _ = _create_arbitrary_principal(ctx)

    _create_access_entry_with_retry(ctx, cluster["name"], principal_arn)
    ctx.on_cleanup(lambda: eks.delete_access_entry(clusterName=cluster["name"], principalArn=principal_arn))

    policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
    eks.associate_access_policy(
        clusterName=cluster["name"],
        principalArn=principal_arn,
        policyArn=policy_arn,
        accessScope={"type": "cluster"},
    )

    associated = eks.list_associated_access_policies(clusterName=cluster["name"], principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    assert [p["policyArn"] for p in associated] == [policy_arn], associated

    eks.disassociate_access_policy(clusterName=cluster["name"], principalArn=principal_arn, policyArn=policy_arn)

    remaining = eks.list_associated_access_policies(clusterName=cluster["name"], principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    assert remaining == [], remaining


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


def _default_subnets(ctx, min_azs=2):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())
    if len(ids) < min_azs:
        raise AssertionError(
            "account/region has no shared network VPC with >=2 AZ subnets required for EKS "
            "cluster creation; provision one to close this gap"
        )
    return ids[:min_azs]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
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
    return role["Arn"]


def _create_cluster_with_retry(eks, timeout_s=120.0, **kwargs):
    """A freshly created cluster role can take a few seconds to propagate before
    EKS will accept it; retry the specific "invalid role" rejection until it does,
    or the bounded timeout expires."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "InvalidParameterException":
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"create_cluster never accepted the cluster role (IAM propagation?): {last_err}")


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _default_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real": "1"},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    _create_cluster_with_retry(eks, **kwargs)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE: {cluster['status']}")
    return {"name": name, "arn": cluster["arn"], "role_arn": role_arn, "subnet_ids": subnet_ids}


def _create_access_entry_with_retry(ctx, cluster_name, principal_arn, timeout_s=120.0):
    """A freshly created principal role can take a few seconds to propagate before
    EKS will accept it as a valid access-entry principal; retry the specific
    "invalid principal" rejection until it does, or the bounded timeout expires."""
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            return
        except ClientError as exc:
            last_err = exc
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterException" and "principal" in str(exc).lower():
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_access_entry never accepted the principal (IAM propagation?): {last_err}")


def _create_arbitrary_principal(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-principal-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"], role_name



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
