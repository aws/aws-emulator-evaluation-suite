"""nodegroup-release-version-matches-optimized-ami-release-format."""

from __future__ import annotations

import datetime
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodegroup-release-version-matches-optimized-ami-release-format"
GROUP = "representation"
SERVICES = ["eks"]

PREFIX = "sim2real-behav-"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_ROLE_PROPAGATION_TIMEOUT_S = 90
_CLUSTER_WAIT_TIMEOUT_S = 1500
_NODEGROUP_WAIT_TIMEOUT_S = 900
_CLEANUP_TIMEOUT_S = 1200.0
_NODE_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
]
_AMI_TYPE = "AL2023_x86_64_STANDARD"
#: An EKS optimized Amazon Linux AMI release: Kubernetes major.minor.patch, a dash, the build date.
_RELEASE_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)-(\d{8})")


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


def _create_role(ctx, trust_service: str, prefix: str, policy_arns: list[str]) -> str:
    """A role owned by this check; its detach and delete are registered before each step."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(PREFIX + prefix)
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


def _create_active_cluster(ctx, eks) -> str:
    role_arn = _create_role(ctx, "eks.amazonaws.com", "eks-cl-role-", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + "eks-rv-")
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, name))
    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    deadline = _deadline(ctx, _ROLE_PROPAGATION_TIMEOUT_S)
    while True:
        try:
            eks.create_cluster(
                name=name,
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


def _delete_nodegroup_and_wait(eks, cluster: str, nodegroup: str) -> None:
    """Delete the nodegroup and wait until it is gone, so the cluster and node role can follow."""
    deadline = time.monotonic() + _CLEANUP_TIMEOUT_S
    while True:
        try:
            eks.delete_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(15)
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(
        f"nodegroup {nodegroup} still exists {_CLEANUP_TIMEOUT_S:.0f}s after DeleteNodegroup"
    )


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed nodegroup reports the release version of the EKS optimized AMI it runs.

    Without a launch template, releaseVersion is <kubernetes major.minor.patch>-<YYYYMMDD> and its
    major.minor is the cluster's Kubernetes version.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html
    """
    eks = ctx.client("eks")
    node_role = _create_role(ctx, "ec2.amazonaws.com", "eks-node-role-", _NODE_POLICIES)
    cluster = _create_active_cluster(ctx, eks)
    cluster_version = eks.describe_cluster(name=cluster)["cluster"]["version"]

    nodegroup = ctx.unique_name(PREFIX + "ng-")
    ctx.on_cleanup(lambda: _delete_nodegroup_and_wait(eks, cluster, nodegroup))
    # A fresh role is refused with InvalidParameterException until IAM propagates it.
    deadline = _deadline(ctx, _ROLE_PROPAGATION_TIMEOUT_S)
    while True:
        try:
            eks.create_nodegroup(
                clusterName=cluster,
                nodegroupName=nodegroup,
                subnets=_subnet_ids(ctx),
                nodeRole=node_role,
                amiType=_AMI_TYPE,
                instanceTypes=["t3.small"],
                scalingConfig={"minSize": 0, "maxSize": 1, "desiredSize": 0},
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

    active = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)["nodegroup"],
        lambda n: n["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        deadline=_deadline(ctx, _NODEGROUP_WAIT_TIMEOUT_S),
        interval_s=15,
        desc=f"nodegroup {nodegroup} ACTIVE",
    )
    assert active["status"] == "ACTIVE", (
        f"nodegroup landed in {active['status']!r}: {active.get('health')}"
    )
    assert active["amiType"] == _AMI_TYPE, (
        f"amiType must round-trip as {_AMI_TYPE}, got {active.get('amiType')!r}"
    )
    assert active["version"] == cluster_version, (
        f"nodegroup version must default to the cluster version {cluster_version}, "
        f"got {active.get('version')!r}"
    )
    release = active.get("releaseVersion")
    match = _RELEASE_VERSION.fullmatch(release or "")
    assert match, f"releaseVersion must look like <major.minor.patch>-<YYYYMMDD>, got {release!r}"
    assert f"{match.group(1)}.{match.group(2)}" == cluster_version, (
        f"releaseVersion {release!r} must be built for Kubernetes {cluster_version}"
    )
    try:
        datetime.datetime.strptime(match.group(4), "%Y%m%d")
    except ValueError as exc:
        raise AssertionError(
            f"releaseVersion {release!r} must end in a YYYYMMDD build date"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
