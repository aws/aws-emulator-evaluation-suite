"""cluster-update-version-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-update-version-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
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


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
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


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    return _ensure_role(ctx, ctx.unique_name(PREFIX + label), "ec2.amazonaws.com")


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


def _active_cluster(ctx, c, suffix):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={
            "subnetIds": _subnet_ids(ctx),
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={
            "authenticationMode": "API_AND_CONFIG_MAP",
            "bootstrapClusterCreatorAdminPermissions": True,
        },
        tags={"sim2real": "1"},
    )
    # IAM is eventually consistent: EKS can reject a brand-new role for a few seconds
    # after creation with InvalidParameterException before it propagates. Retry on that
    # specific error with a deadline instead of sleeping blind before ever trying.
    deadline = time.monotonic() + 60
    while True:
        try:
            c.create_cluster(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
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

import uuid


@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateClusterVersion to an unsupported version fails with InvalidParameterException "unsupported
    Kubernetes version" and on an absent cluster with ResourceNotFoundException, creating no update, and
    DescribeUpdate of an unknown id fails with ResourceNotFoundException; exact messages throughout.
    """
    c = ctx.client("eks")
    if not hasattr(c, "describe_cluster_versions"):
        raise AssertionError("botocore in this environment exposes no eks.describe_cluster_versions")
    name = _active_cluster(ctx, c, "eks-upv-")
    version = c.describe_cluster(name=name)["cluster"]["version"]

    catalog = c.describe_cluster_versions()["clusterVersions"]
    assert catalog, f"describe_cluster_versions returned no versions: {catalog!r}"
    assert all(entry.get("clusterVersion") for entry in catalog), (
        f"a describe_cluster_versions entry is missing clusterVersion: {catalog!r}"
    )

    before = set(c.list_updates(name=name)["updateIds"])

    code, message = _error(lambda: c.update_cluster_version(name=name, version="9.99"))
    assert code == "InvalidParameterException", (
        f"an unsupported target version should be rejected with InvalidParameterException, got {code!r}"
    )
    assert message == "unsupported Kubernetes version", (
        f"unsupported target version rejected with message {message!r}"
    )
    absent_name = ctx.unique_name("absent-clu-")
    code, message = _error(lambda: c.update_cluster_version(name=absent_name, version=version))
    assert code == "ResourceNotFoundException", (
        f"UpdateClusterVersion against a nonexistent cluster {absent_name!r} should 404, got {code!r}"
    )
    expected = f"No cluster found for name: {absent_name}."
    assert message == expected, f"UpdateClusterVersion on {absent_name!r} -> {message!r}, expected {expected!r}"
    # A rejected upgrade must not leave a phantom update record behind.
    after_rejections = set(c.list_updates(name=name)["updateIds"])
    assert after_rejections == before, (
        f"a rejected UpdateClusterVersion left phantom update(s): {after_rejections - before!r}"
    )
    status = c.describe_cluster(name=name)["cluster"]["status"]
    assert status == "ACTIVE", f"cluster {name} should still be ACTIVE after rejected updates, got {status!r}"

    unknown = str(uuid.uuid4())
    code, message = _error(lambda: c.describe_update(name=name, updateId=unknown))
    assert code == "ResourceNotFoundException", (
        f"DescribeUpdate for an unknown update id {unknown!r} should 404, got {code!r}"
    )
    expected = f"No update found for ID: {unknown}"
    assert message == expected, f"DescribeUpdate for {unknown!r} -> {message!r}, expected {expected!r}"


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
