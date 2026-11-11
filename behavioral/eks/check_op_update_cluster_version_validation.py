"""op-update-cluster-version-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-update-cluster-version-validation"
GROUP = 'overly-permissive'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_RETIRED_VERSION = "1.15"


def _error_code(fn):
    """Call fn, require it raises ClientError, return the (error Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service):
    import json
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole"],
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


def _create_cluster_retrying_role_propagation(c, timeout_s=60, interval_s=5, **kwargs):
    """IAM is eventually consistent: a just-created role can 404 against EKS for a short window
    after IAM itself reports it. Every other CreateCluster parameter here is known-good, so an
    InvalidParameterException in this narrow window is the role, not the request; retry it on a
    deadline rather than guessing a fixed sleep."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return c.create_cluster(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidParameterException" and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise


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
    _create_cluster_retrying_role_propagation(
        c,
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateClusterVersion resolves the cluster before the version: retired version 1.15, absent from
    DescribeClusterVersions, is InvalidParameterException ("Unsupported Kubernetes minor version update ...")
    on an existing cluster and ResourceNotFoundException naming a missing one."""
    c = ctx.client("eks")
    ghost = ctx.unique_name(PREFIX + "eks-ghost-")

    catalog_versions = {
        entry["clusterVersion"] for entry in c.describe_cluster_versions()["clusterVersions"]
    }
    assert _RETIRED_VERSION not in catalog_versions, (
        f"{_RETIRED_VERSION!r} is unexpectedly present in the current supported-version "
        f"catalog {sorted(catalog_versions)!r}; it cannot serve as a retired-version probe"
    )

    # Positive control: the SAME retired version, against a cluster that DOES exist, is
    # InvalidParameterException -- proving 1.15 is genuinely rejected as an invalid version, not
    # merely that a missing cluster rejects everything.
    name = _active_cluster(ctx, c, "eks-opv-")
    current_version = c.describe_cluster(name=name)["cluster"]["version"]
    control_code, control_msg = _error_code(lambda: c.update_cluster_version(name=name, version=_RETIRED_VERSION))
    assert control_code == "InvalidParameterException", (
        f"retired version {_RETIRED_VERSION!r} against the existing cluster {name!r} -> "
        f"{control_code}, expected InvalidParameterException"
    )
    assert control_msg == (
        f"Unsupported Kubernetes minor version update from {current_version} to {_RETIRED_VERSION}"
    ), f"retired version against the existing cluster -> {control_msg!r}"

    # The call under test: same retired version, but the cluster does not exist at all.
    code, msg = _error_code(lambda: c.update_cluster_version(name=ghost, version=_RETIRED_VERSION))
    assert code == "ResourceNotFoundException", (
        f"retired version {_RETIRED_VERSION!r} against the missing cluster {ghost!r} -> "
        f"{code}, expected ResourceNotFoundException"
    )
    assert msg == f"No cluster found for name: {ghost}.", f"missing cluster -> {msg!r}"


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
