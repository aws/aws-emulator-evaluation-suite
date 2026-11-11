"""capability-server-side-managed-status-transition."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "capability-server-side-managed-status-transition"
GROUP = "server-side"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapability activation is carried out by managed server-side execution: after the
    call returns, DescribeCapability transitions from its initial state to ACTIVE purely from
    EKS-side reconciliation, with no further client action beyond polling."""
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _default_subnets(ctx)
    _create_cluster_with_retry(ctx, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_name))
    cluster = _wait_cluster_status(ctx, cluster_name, {"ACTIVE", "FAILED"})
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster['status']}")

    capability_role_arn = _create_capability_role(ctx)
    capability_name = ctx.unique_name("sim2real-cap-")

    create_resp = _create_capability_with_retry(
        ctx, cluster_name, capability_name, capability_role_arn
    )["capability"]
    ctx.on_cleanup(lambda: eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name))
    assert create_resp["status"] != "ACTIVE", (
        "capability was already ACTIVE at creation time - no server-side transition to observe"
    )

    final = _poll_until(
        lambda: eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)["capability"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=900.0,
        interval_s=20.0,
    )
    assert final["status"] == "ACTIVE"
    assert final["capabilityName"] == capability_name
    assert final["type"] == "KRO"


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


def _create_capability_with_retry(ctx, cluster_name, capability_name, role_arn, timeout_s=180.0, interval_s=10.0):
    # A freshly created IAM role's trust policy can take a short while to propagate through
    # EKS's capabilities service; retry on the specific "trust policy invalid" rejection.
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.create_capability(
                clusterName=cluster_name,
                capabilityName=capability_name,
                type="KRO",
                roleArn=role_arn,
                deletePropagationPolicy="RETAIN",
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "InvalidParameterException" and "trust policy" in message and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _default_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets][:3]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network lacks enough subnets to provision an EKS cluster")
    return subnet_ids


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_capability_role(ctx):
    # KRO capabilities need only the trust policy for capabilities.eks.amazonaws.com - kro
    # operates entirely within the cluster and makes no AWS API calls on its own.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kro-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "capabilities.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, **kwargs):
    eks = ctx.client("eks")
    # A brand-new role is "not authorized" until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                **kwargs,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code != "ClientException" or "not authorized" not in message or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    cluster = None
    while True:
        cluster = eks.describe_cluster(name=name)["cluster"]
        if cluster["status"] in statuses:
            return cluster
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {name} did not reach {statuses} within {timeout_s}s "
                f"(last={cluster['status']})"
            )
        time.sleep(interval_s)


def _delete_cluster(ctx, name):
    _delete_eks_cluster_and_wait(ctx.client("eks"), name)



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
