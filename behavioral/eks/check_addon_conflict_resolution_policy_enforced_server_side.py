"""addon-conflict-resolution-policy-enforced-server-side."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "addon-conflict-resolution-policy-enforced-server-side"
GROUP = "server-side"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAddon for vpc-cni on a fresh cluster reaches ACTIVE, and a second CreateAddon for the
    same addon (resolveConflicts OVERWRITE) is rejected with ResourceInUseException, leaving the
    existing addon's status, ARN and version unchanged and exactly one addon of that name."""
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _default_subnets(ctx)
    _create_cluster_with_retry(ctx, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_name))
    cluster = _wait_cluster_status(ctx, cluster_name, {"ACTIVE", "FAILED"})
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster['status']}")

    addon_name = "vpc-cni"

    # Positive: server-side reconciliation actually installs/drives the addon to ACTIVE -
    # this is real managed reconciliation, not just an echoed request record.
    eks.create_addon(
        clusterName=cluster_name,
        addonName=addon_name,
        resolveConflicts="NONE",
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: eks.delete_addon(clusterName=cluster_name, addonName=addon_name))
    final = _poll_until(
        lambda: eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"],
        lambda a: a["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert final["status"] == "ACTIVE", f"expected ACTIVE, got {final['status']!r}"
    original_arn = final["addonArn"]
    original_version = final["addonVersion"]

    # Rejection: a second CreateAddon for the same already-existing addon is rejected
    # server-side, regardless of resolveConflicts - the existing managed record is
    # authoritative and isn't silently overwritten/re-echoed.
    dup_code = _expect_error(
        lambda: eks.create_addon(clusterName=cluster_name, addonName=addon_name, resolveConflicts="OVERWRITE")
    )
    assert dup_code == ("ResourceInUseException", "Addon already exists."), f"expected ResourceInUseException, got {dup_code!r}"

    # Effect absent: the original addon record is untouched by the rejected duplicate call -
    # same status, same ARN, same version, and still exactly one addon of this name.
    still = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
    assert still["status"] == "ACTIVE", f"expected ACTIVE, got {still['status']!r}"
    assert still["addonArn"] == original_arn, "addon ARN must not change after a rejected duplicate create"
    assert still["addonVersion"] == original_version, "addon version must not change after a rejected duplicate create"
    listed = eks.list_addons(clusterName=cluster_name)["addons"]
    assert listed.count(addon_name) == 1, f"expected exactly one {addon_name!r} addon, found {listed!r}"


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS refuses must not be mistaken for a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


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
                tags={"sim2real": "1"},
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
