"""list-associated-access-policies-unknown-principal-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-associated-access-policies-unknown-principal-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]

_VIEW_POLICY_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssociatedAccessPolicies for a principal with no access entry on an ACTIVE cluster
    returns ResourceNotFoundException rather than an empty list, while a principal with an access
    entry and associated policy gets that policy back."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    role_with_entry = _throwaway_iam_role(ctx)
    role_without_entry = _throwaway_iam_role(ctx)

    _retry_iam_propagation(
        lambda: eks.create_access_entry(clusterName=cluster_name, principalArn=role_with_entry, type="STANDARD")
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: eks.delete_access_entry(clusterName=cluster_name, principalArn=role_with_entry)
        )
    )
    eks.associate_access_policy(
        clusterName=cluster_name,
        principalArn=role_with_entry,
        policyArn=_VIEW_POLICY_ARN,
        accessScope={"type": "cluster"},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: eks.disassociate_access_policy(
                clusterName=cluster_name, principalArn=role_with_entry, policyArn=_VIEW_POLICY_ARN
            )
        )
    )

    # Positive control: the principal WITH an access entry + associated policy succeeds.
    positive = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=role_with_entry)
    policy_arns = [p["policyArn"] for p in positive["associatedAccessPolicies"]]
    assert _VIEW_POLICY_ARN in policy_arns, f"expected {_VIEW_POLICY_ARN} in {policy_arns}"

    # Negative: the principal WITHOUT any access entry on the same, real cluster.
    code, msg = _error_code(
        lambda: eks.list_associated_access_policies(clusterName=cluster_name, principalArn=role_without_entry)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert msg == "The requested resource does not exist.", f"unexpected message: {msg!r}"


def _error_code(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_iam_propagation(fn, deadline_s=90):
    """A just-created IAM role is not immediately recognized by EKS as a valid
    principal (observed on real AWS as InvalidParameterException: "invalid
    principal"); retry the side-effect-free-on-failure call until it propagates."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _throwaway_iam_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-eks-principal-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": account_id}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _iam_role_for_eks_cluster(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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


def _create_active_cluster(ctx, authentication_mode="API"):
    eks = ctx.client("eks")
    role_arn = _iam_role_for_eks_cluster(ctx)
    subnet_ids = _default_vpc_subnet_ids(ctx)
    name = ctx.unique_name("sim2real-eks-")

    _retry_iam_propagation(
        lambda: eks.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
            accessConfig={"authenticationMode": authentication_mode},
        )
    )

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
