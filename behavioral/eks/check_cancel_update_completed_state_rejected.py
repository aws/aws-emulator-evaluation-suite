"""cancel-update-completed-state-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-update-completed-state-rejected"
GROUP = "error-semantics"
SERVICES = ["eks"]

_AUTO_MODE_CLUSTER_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSComputePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicyV2",
    "arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy",
]
_AUTO_MODE_NODE_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodeMinimalPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an Auto Mode cluster upgraded N-1 to N, a rollback to N-1 is a VersionRollback update that
    CancelUpdate takes to Cancelled with the cluster staying on N, while cancelling a completed logging
    update fails with InvalidParameterException and leaves it Successful.
    """
    eks = ctx.client("eks")
    older_version, newer_version = _pick_upgrade_versions(eks)
    cluster_name = _create_active_auto_mode_cluster(ctx, older_version)

    before = eks.describe_cluster(name=cluster_name)["cluster"]
    assert before["version"] == older_version, before

    upgrade = eks.update_cluster_version(name=cluster_name, version=newer_version)["update"]
    _poll_until(
        ctx,
        lambda: eks.describe_update(name=cluster_name, updateId=upgrade["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=3600.0,
    )
    upgraded = eks.describe_cluster(name=cluster_name)["cluster"]
    assert upgraded["version"] == newer_version, upgraded
    assert upgraded["status"] == "ACTIVE", upgraded

    # A different, unrelated update completes on the same cluster before the rollback is
    # ever requested -- this is the negative leg's target.
    config_update = eks.update_cluster_config(
        name=cluster_name, logging={"clusterLogging": [{"types": ["api"], "enabled": True}]}
    )["update"]
    config_update_id = config_update["id"]
    completed = _poll_until(
        ctx,
        lambda: eks.describe_update(name=cluster_name, updateId=config_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed"),
        timeout_s=600.0,
    )
    assert completed["status"] == "Successful", f"logging update should complete Successfully, got {completed}"

    # Positive control: requesting the previous minor version is recognized as a
    # VersionRollback update, and cancelling it while InProgress reaches Cancelled.
    rollback = eks.update_cluster_version(name=cluster_name, version=older_version)["update"]
    assert rollback["type"] == "VersionRollback", rollback

    eks.cancel_update(name=cluster_name, updateId=rollback["id"])
    final_rollback = _poll_until(
        ctx,
        lambda: eks.describe_update(name=cluster_name, updateId=rollback["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=900.0,
    )
    assert final_rollback["status"] == "Cancelled", (
        f"positive control failed: cancelling the in-flight VersionRollback should reach Cancelled, got {final_rollback}"
    )
    after_rollback = eks.describe_cluster(name=cluster_name)["cluster"]
    assert after_rollback["version"] == newer_version, (
        f"control plane must never roll back once the rollback was cancelled, got {after_rollback}"
    )

    # Negative: cancelling the earlier, already-completed logging update is rejected.
    code, message = _error(lambda: eks.cancel_update(name=cluster_name, updateId=config_update_id))
    assert code == "InvalidParameterException", (
        f"cancelling an already-completed, non-rollback update should be rejected with "
        f"InvalidParameterException, got {code!r}"
    )
    assert message == "Update is not in a cancellable state. Supported update types: VersionRollback", message

    unaffected = eks.describe_update(name=cluster_name, updateId=config_update_id)["update"]
    assert unaffected["status"] == "Successful", "rejected cancel must not alter a completed update"


def _pick_upgrade_versions(eks) -> tuple[str, str]:
    versions = eks.describe_cluster_versions(clusterType="eks")["clusterVersions"]
    supported = sorted(
        {v["clusterVersion"] for v in versions if v.get("versionStatus") in ("STANDARD_SUPPORT", "EXTENDED_SUPPORT")},
        key=lambda v: tuple(int(p) for p in v.split(".")),
    )
    if len(supported) < 2:
        raise AssertionError(f"need at least two supported cluster versions, got {supported}")
    older, newer = supported[-2], supported[-1]
    older_minor = int(older.split(".")[1])
    newer_minor = int(newer.split(".")[1])
    if newer_minor - older_minor != 1:
        raise AssertionError(f"expected adjacent minor versions, got {older} -> {newer}")
    return older, newer


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"waiting on {last!r}: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _retry_delete(fn: Callable[[], Any], timeout_s: float = 600.0) -> None:
    """Delete, retrying DependencyViolation while ENIs drain; a not-found answer means it is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_network(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    if len(az_names) < 2:
        raise AssertionError("region needs at least two availability zones")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, trust_service: str, name_prefix: str, policy_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    return role_arn


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 1200.0) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {name} still describes {timeout_s}s after DeleteCluster")


def _create_active_auto_mode_cluster(ctx, version: str) -> str:
    eks = ctx.client("eks")
    subnet_ids = _create_network(ctx)
    cluster_role_arn = _create_role(ctx, "eks.amazonaws.com", "sim2real-eks-clusterrole-", _AUTO_MODE_CLUSTER_POLICIES)
    node_role_arn = _create_role(ctx, "ec2.amazonaws.com", "sim2real-eks-noderole-", _AUTO_MODE_NODE_POLICIES)
    name = ctx.unique_name("sim2real-eks-cluster-")

    create_kwargs = {
        "name": name,
        "version": version,
        "roleArn": cluster_role_arn,
        "resourcesVpcConfig": {"subnetIds": subnet_ids},
        "accessConfig": {"authenticationMode": "API"},
        "kubernetesNetworkConfig": {"elasticLoadBalancing": {"enabled": True}},
        "storageConfig": {"blockStorage": {"enabled": True}},
        "computeConfig": {"enabled": True, "nodePools": ["general-purpose"], "nodeRoleArn": node_role_arn},
        "tags": {"sim2real:check": CHECK},
    }

    # The cluster and node roles just created take a few seconds to propagate before EKS accepts
    # them; that InvalidParameterException is retried to a bounded deadline.
    deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            eks.create_cluster(**create_kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("creating the cluster while its new role propagates: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))

    active = _poll_until(
        ctx,
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
    )
    if active["status"] != "ACTIVE":
        raise AssertionError(f"cluster ended in status {active['status']}: {active}")
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
