"""cancel-update-version-rollback-transitions-to-cancelled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cancel-update-version-rollback-transitions-to-cancelled"
GROUP = "state-machine"
SERVICES = ["eks"]

_CLUSTER_WAIT_TIMEOUT_S = 20 * 60
_CLUSTER_POLL_INTERVAL_S = 20
_UPGRADE_WAIT_TIMEOUT_S = 60 * 60
_UPGRADE_POLL_INTERVAL_S = 30
_CANCEL_WAIT_TIMEOUT_S = 15 * 60
_CANCEL_POLL_INTERVAL_S = 5
#: All teardowns of one run share one retry deadline inside the suite's cleanup budget.
_CLEANUP_S = 1800.0

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


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On an Auto Mode cluster upgraded to N, requesting N-1 creates a VersionRollback update;
    CancelUpdate during node rollback moves it InProgress -> Cancelled, the control plane stays on
    N, and the cluster stays ACTIVE.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/rollback-automode.html
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    eks = ctx.client("eks")
    older_version, newer_version = _pick_upgrade_versions(ctx)
    cluster_name = _create_active_auto_mode_cluster(ctx, older_version, teardown_deadline)

    before = eks.describe_cluster(name=cluster_name)["cluster"]
    assert before["version"] == older_version, before

    upgrade = eks.update_cluster_version(name=cluster_name, version=newer_version)["update"]
    _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=upgrade["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=_UPGRADE_WAIT_TIMEOUT_S,
        interval_s=_UPGRADE_POLL_INTERVAL_S,
    )
    upgraded = eks.describe_cluster(name=cluster_name)["cluster"]
    assert upgraded["version"] == newer_version, upgraded
    assert upgraded["status"] == "ACTIVE", upgraded

    rollback = _request_rollback(ctx, cluster_name, older_version)
    assert rollback["type"] == "VersionRollback", rollback

    # Race the cancellable node-rollback window as tightly as possible.
    eks.cancel_update(name=cluster_name, updateId=rollback["id"])

    final_update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=rollback["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=_CANCEL_WAIT_TIMEOUT_S,
        interval_s=_CANCEL_POLL_INTERVAL_S,
    )
    assert final_update["status"] == "Cancelled", final_update

    after = eks.describe_cluster(name=cluster_name)["cluster"]
    assert after["status"] == "ACTIVE", after
    assert after["version"] == newer_version, (
        f"control plane must never roll back once the rollback was cancelled, got {after}"
    )




def _request_rollback(ctx, cluster_name: str, version: str) -> dict:
    """UpdateClusterVersion to `version`, retrying the refusal AWS returns while a follow-up
    update of the finished upgrade is still in progress on the cluster."""
    eks = ctx.client("eks")
    left = ctx.time_left()
    deadline = time.monotonic() + (_CANCEL_WAIT_TIMEOUT_S if left is None else min(_CANCEL_WAIT_TIMEOUT_S, left - 60.0))
    while True:
        try:
            return eks.update_cluster_version(name=cluster_name, version=version)["update"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx, teardown_deadline) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_delete(ctx, lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound", teardown_deadline)
    )

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    assert len(az_names) >= 2, "region needs at least two availability zones"

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _retry_delete(
                ctx, lambda: ec2.delete_subnet(SubnetId=sid), "InvalidSubnetID.NotFound", teardown_deadline
            )
        )
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, trust_service: str, name_prefix: str, policy_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    return role_arn


def _cleanup_deadline(teardown_deadline) -> float:
    """The monotonic instant all of this run's teardowns stop retrying at."""
    return teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S)


def _delete_cluster_and_wait(ctx, name: str, teardown_deadline) -> None:
    """Delete the cluster and wait until it is gone; an in-use refusal retries, others raise."""
    eks = ctx.client("eks")
    _retry_delete(ctx, lambda: eks.delete_cluster(name=name), "ResourceNotFoundException",
                  teardown_deadline, busy="ResourceInUseException")
    while True:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= _cleanup_deadline(teardown_deadline):
            raise AssertionError(f"cluster {name} still exists at the cleanup deadline")
        time.sleep(2)


def _retry_delete(ctx, fn, gone: str, teardown_deadline, busy: str = "DependencyViolation") -> None:
    """Run the delete; return on its not-found code, retry `busy` every 2 s, raise the rest."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone:
                return
            if code != busy or time.monotonic() >= _cleanup_deadline(teardown_deadline):
                raise
        time.sleep(2)


def _pick_upgrade_versions(ctx) -> tuple[str, str]:
    eks = ctx.client("eks")
    versions = eks.describe_cluster_versions(clusterType="eks")["clusterVersions"]
    supported = sorted(
        {v["clusterVersion"] for v in versions if v.get("versionStatus") in ("STANDARD_SUPPORT", "EXTENDED_SUPPORT")},
        key=lambda v: tuple(int(p) for p in v.split(".")),
    )
    assert len(supported) >= 2, f"need at least two supported cluster versions, got {supported}"
    older, newer = supported[-2], supported[-1]
    older_minor = int(older.split(".")[1])
    newer_minor = int(newer.split(".")[1])
    assert newer_minor - older_minor == 1, f"expected adjacent minor versions, got {older} -> {newer}"
    return older, newer


def _create_active_auto_mode_cluster(ctx, version: str, teardown_deadline) -> str:
    eks = ctx.client("eks")
    subnet_ids = _create_network(ctx, teardown_deadline)
    cluster_role_arn = _create_role(
        ctx, "eks.amazonaws.com", "sim2real-eks-clusterrole-", _AUTO_MODE_CLUSTER_POLICIES
    )
    node_role_arn = _create_role(
        ctx, "ec2.amazonaws.com", "sim2real-eks-noderole-", _AUTO_MODE_NODE_POLICIES
    )
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
    }

    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (80.0 if left is None else min(80.0, left))
    while True:
        try:
            eks.create_cluster(**create_kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name, teardown_deadline))

    active = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_WAIT_TIMEOUT_S,
        interval_s=_CLUSTER_POLL_INTERVAL_S,
    )
    assert active["status"] == "ACTIVE", f"cluster ended in status {active['status']}"
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
