"""cancel-update-unknown-update-id-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-update-unknown-update-id-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an ACTIVE managed cluster (a connected one answers ClientException for any update id), CancelUpdate
    and DescribeUpdate with a never-issued update id fail with ResourceNotFoundException and their exact
    messages, ListUpdates omits it, and an unknown cluster fails first with ResourceNotFoundException.
    """
    eks = ctx.client("eks")

    fake_cluster = ctx.unique_name("sim2real-eks-nonexistent-")
    fake_update_id = str(uuid.uuid4())
    unknown_cluster = _error(
        lambda: eks.cancel_update(name=fake_cluster, updateId=fake_update_id)
    )
    assert unknown_cluster == ("ResourceNotFoundException", f"No cluster found for name: {fake_cluster}."), (
        f"unknown cluster: expected ResourceNotFoundException, got {unknown_cluster!r}"
    )

    cluster_name = _active_cluster(ctx, eks)
    unknown_update_id = str(uuid.uuid4())
    cancel = _error(
        lambda: eks.cancel_update(name=cluster_name, updateId=unknown_update_id)
    )
    assert cancel == ("ResourceNotFoundException", f"Update {unknown_update_id} not found"), (
        f"real ACTIVE cluster {cluster_name!r} + never-issued update id: expected "
        f"ResourceNotFoundException, got {cancel!r} (unknown-cluster case gave "
        f"{unknown_cluster!r})"
    )

    describe = _error(
        lambda: eks.describe_update(name=cluster_name, updateId=unknown_update_id)
    )
    assert describe == ("ResourceNotFoundException", f"No update found for ID: {unknown_update_id}"), (
        f"DescribeUpdate for the same fabricated id {unknown_update_id!r} on "
        f"{cluster_name!r}: expected ResourceNotFoundException, got {describe!r} "
        f"(cancel_update gave {cancel!r})"
    )

    update_ids = eks.list_updates(name=cluster_name).get("updateIds", [])
    assert unknown_update_id not in update_ids, (
        f"fabricated update id {unknown_update_id!r} must not appear in "
        f"{cluster_name}'s update history: {update_ids}"
    )


def _error(fn):
    """Call fn, require it raises ClientError, return its (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service, extra_actions=()):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _retry_on(fn, codes, timeout_s=420, interval_s=20):
    """Call fn, retrying while it fails with one of *codes* (genuinely-eventual EKS behavior)."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in codes or time.time() >= deadline:
                raise
            time.sleep(interval_s)


def _active_cluster(ctx, c):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + "eks-cunf-")
    _retry_on(
        lambda: c.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={
                "subnetIds": _subnet_ids(ctx),
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
            tags={"sim2real": "1"},
        ),
        # CLUSTER_ROLE is adopted, not always freshly created, but a first-ever
        # run in a fresh account still needs IAM propagation before EKS can
        # assume it.
        {"InvalidParameterException"},
        timeout_s=90, interval_s=10,
    )
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"
    return name


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
