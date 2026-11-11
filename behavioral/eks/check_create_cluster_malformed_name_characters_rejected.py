"""create-cluster-malformed-name-characters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-malformed-name-characters-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster with a name outside ^[0-9A-Za-z][A-Za-z0-9\\-_]*$ is rejected with
    InvalidParameterException and creates no cluster, while a valid name on the same
    role/VPC reaches ACTIVE."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _get_subnets(ctx)

    bad_name = "sim2real bad cluster name !@#$"
    code, message = _expect_error(
        lambda: eks.create_cluster(name=bad_name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        'The parameter name contains invalid characters. It should conform to the regular '
        'expression "^[0-9A-Za-z][A-Za-z0-9-_]*"In other words, it should start with a number '
        'or letter, and can contain numbers, letters, dashes, and underscores.'
    ), message

    # effect absent: no cluster with that (invalid) name exists among real clusters.
    # (describe_cluster on a malformed name can itself be rejected for the same
    # InvalidParameterException reason, so list_clusters is the reliable non-existence probe.)
    existing = eks.list_clusters().get("clusters", [])
    assert bad_name not in existing, f"malformed name {bad_name!r} unexpectedly present in list_clusters: {existing!r}"

    # positive control: a syntactically valid name on identical role/VPC succeeds
    good_name, cluster = _create_active_cluster(ctx, role_arn, subnet_ids)
    assert cluster["name"] == good_name, f"expected created cluster name {good_name!r}, got {cluster['name']!r}"
    assert cluster["status"] == "ACTIVE", f"expected cluster {good_name!r} to reach ACTIVE, got {cluster['status']!r}"


# ===== helpers =====
_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, so
    accepting input AWS refuses fails as acceptance rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _get_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    assert len(subnet_ids) >= 2, f"need >=2 AZ-distinct subnets in vpc {vpc_id}, found {subnet_ids}"
    return subnet_ids[:3]


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_active_cluster(ctx, role_arn: str, subnet_ids: list[str]):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-cl-")
    # A brand-new IAM role is rejected with InvalidParameterException until it propagates.
    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name, cluster



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
