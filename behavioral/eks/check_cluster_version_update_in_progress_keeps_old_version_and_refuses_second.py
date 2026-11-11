"""cluster-version-update-in-progress-keeps-old-version-and-refuses-second."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-version-update-in-progress-keeps-old-version-and-refuses-second"
GROUP = "state-machine"
SERVICES = ["eks"]

PREFIX = "sim2real-behav-"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_ROLE_PROPAGATION_TIMEOUT_S = 90
_CLUSTER_WAIT_TIMEOUT_S = 1500
_UPGRADE_WAIT_TIMEOUT_S = 2400
#: Bound on DescribeCluster leaving ACTIVE after UpdateClusterVersion; the status change lags the
#: accepted update.
_STATUS_SETTLE_S = 180
_CLEANUP_TIMEOUT_S = 1200.0
#: The refusal of a second UpdateClusterVersion while a VersionUpdate runs; formatted with the
#: cluster name and the in-flight update id.
_SECOND_VERSION_UPDATE = (
    "ResourceInUseException",
    "Cannot VersionUpdate because cluster {cluster} currently has update {update_id} in progress",
)


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _reserved_s(ctx, cap_s: float, reserve_s: float) -> float:
    """cap_s less the time later waits need, but never under what a fast target needs."""
    left = ctx.time_left()
    if left is None or not reserve_s:
        return cap_s
    return min(cap_s, max(min(60.0, left - 5.0), left - reserve_s))


def _deadline(ctx, cap_s: float, reserve_s: float = 300.0) -> float:
    """A monotonic deadline of cap_s, shortened by _reserved_s to leave the teardowns time."""
    return time.monotonic() + _reserved_s(ctx, cap_s, reserve_s)


def _poll_until(probe, predicate, *, deadline: float, interval_s: float, desc: str):
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _create_role(ctx, trust_service: str, policy_arns: list[str]) -> str:
    """A role owned by this check; its detach and delete are registered before each step."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(PREFIX + "eks-cl-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust_service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"][
        "Arn"
    ]
    for policy_arn in policy_arns:
        ctx.on_cleanup(
            lambda p=policy_arn: _gone_ok(
                lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=p), "NoSuchEntity"
            )
        )
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _gone_ok(fn, gone_code: str) -> None:
    """Run a teardown call; the resource already being gone is done, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != gone_code:
            raise


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(
            f"the run's shared network subnets {ctx.network().subnet_ids} are not visible"
        )
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _pick_upgrade_versions(eks) -> tuple[str, str]:
    """The two newest standard-support versions, which are adjacent minors."""
    versions = []
    kwargs = {"clusterType": "eks", "versionStatus": "STANDARD_SUPPORT"}
    while True:
        page = eks.describe_cluster_versions(**kwargs)
        versions.extend(page["clusterVersions"])
        if not page.get("nextToken"):
            break
        kwargs["nextToken"] = page["nextToken"]
    supported = sorted(
        {v["clusterVersion"] for v in versions if v.get("versionStatus") == "STANDARD_SUPPORT"},
        key=lambda v: tuple(int(p) for p in v.split(".")),
    )
    assert len(supported) >= 2, (
        f"need at least two standard-support cluster versions, got {supported}"
    )
    older, newer = supported[-2], supported[-1]
    assert int(newer.split(".")[1]) - int(older.split(".")[1]) == 1, (
        f"expected adjacent minor versions, got {older} -> {newer}"
    )
    return older, newer


def _delete_cluster_and_wait(eks, name: str) -> None:
    """Delete the cluster and wait until it is gone; an in-use refusal retries, others raise."""
    deadline = time.monotonic() + _CLEANUP_TIMEOUT_S
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(20)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(20)
    raise AssertionError(
        f"EKS cluster {name} still exists {_CLEANUP_TIMEOUT_S:.0f}s after DeleteCluster"
    )


def _create_active_cluster(ctx, eks, version: str) -> str:
    role_arn = _create_role(ctx, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + "eks-vu-")
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, name))
    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    deadline = _deadline(ctx, _ROLE_PROPAGATION_TIMEOUT_S)
    while True:
        try:
            eks.create_cluster(
                name=name,
                version=version,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": _subnet_ids(ctx),
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={"authenticationMode": "API"},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "InvalidParameterException"
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        deadline=_deadline(ctx, _CLUSTER_WAIT_TIMEOUT_S),
        interval_s=20,
        desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name} reached {cluster['status']}, expected ACTIVE"
    )
    return name


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A VersionUpdate keeps the old version visible and refuses a second one while it runs.

    While it is InProgress DescribeCluster reports the old version with status UPDATING and a second
    UpdateClusterVersion fails with ResourceInUseException; once Successful the new version shows.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html
    """
    eks = ctx.client("eks")
    older, newer = _pick_upgrade_versions(eks)
    cluster = _create_active_cluster(ctx, eks, older)

    update = eks.update_cluster_version(name=cluster, version=newer)["update"]
    update_id = update["id"]
    assert update["type"] == "VersionUpdate", update
    assert update["status"] == "InProgress", update
    params = {p["type"]: p["value"] for p in update["params"]}
    assert params.get("Version") == newer, (
        f"update params must carry Version={newer}, got {update['params']}"
    )

    during = _poll_until(
        lambda: eks.describe_cluster(name=cluster)["cluster"],
        lambda c: c["status"] != "ACTIVE",
        deadline=_deadline(ctx, _STATUS_SETTLE_S),
        interval_s=5,
        desc=f"cluster {cluster} to leave ACTIVE after UpdateClusterVersion",
    )
    assert during["version"] == older, (
        f"DescribeCluster must report the old version {older} while the update runs, "
        f"got {during['version']}"
    )
    assert during["status"] == "UPDATING", (
        f"cluster status must be UPDATING during the upgrade, got {during['status']}"
    )

    code, message = _error(lambda: eks.update_cluster_version(name=cluster, version=newer))
    want_code, want_message = _SECOND_VERSION_UPDATE
    want_message = want_message.format(cluster=cluster, update_id=update_id)
    assert (code, message) == (want_code, want_message), (
        "a second UpdateClusterVersion during a VersionUpdate must fail with "
        f"{(want_code, want_message)!r}, got {(code, message)!r}"
    )
    ids = eks.list_updates(name=cluster)["updateIds"]
    assert ids == [update_id], f"the refused update must not be recorded; ListUpdates={ids}"

    final = _poll_until(
        lambda: eks.describe_update(name=cluster, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        deadline=_deadline(ctx, _UPGRADE_WAIT_TIMEOUT_S),
        interval_s=30,
        desc=f"update {update_id} to leave InProgress",
    )
    assert final["status"] == "Successful", f"version update finished as {final['status']}: {final}"
    after = eks.describe_cluster(name=cluster)["cluster"]
    assert after["version"] == newer, (
        f"a finished upgrade must report version {newer}, got {after['version']}"
    )
    assert after["status"] == "ACTIVE", (
        f"cluster must be ACTIVE after the upgrade, got {after['status']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
