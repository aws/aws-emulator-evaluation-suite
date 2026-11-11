"""access-policy-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-policy-association-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error_code(fn):
    """Call fn, require it raises ClientError, return the error Code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
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


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=(), cleanup=False):
    """Create-or-reuse an IAM role and return its ARN. `cleanup=True` registers teardown for
    a role this check owns exclusively (a fresh, unique per-run name). The shared, fixed-name
    cluster role is never torn down here, so concurrent and future runs keep reusing it."""
    iam = ctx.client("iam")
    created = False
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
        created = True
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
    if cleanup and created:
        def _delete_role():
            for policy_arn in managed_policies:
                try:
                    iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            try:
                iam.delete_role(RoleName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_delete_role)
    return arn


def _retry_role_propagation(fn, timeout_s=90, interval_s=10, desc=""):
    """Call fn; retry on EKS's InvalidParameterException while a freshly created IAM
    role has not yet propagated, up to a bounded deadline. Any other error, or the same
    error past the deadline, is raised immediately."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.time() >= deadline:
                raise
            time.sleep(interval_s)


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    return _ensure_role(ctx, ctx.unique_name(PREFIX + label), "ec2.amazonaws.com", cleanup=True)


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
    _retry_role_propagation(
        lambda: c.create_cluster(
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
        ),
        desc=f"CreateCluster {name} (cluster role propagation)",
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

VIEW_POLICY_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateAccessPolicy shows up in ListAssociatedAccessPolicies and vanishes on disassociate."""
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-ap-")

    catalog = c.list_access_policies()["accessPolicies"]
    arns = [p["arn"] for p in catalog]
    assert VIEW_POLICY_ARN in arns, arns

    principal = _principal_role(ctx)
    _retry_role_propagation(
        lambda: c.create_access_entry(
            clusterName=cluster, principalArn=principal, tags={"sim2real": "1"}
        ),
        desc=f"CreateAccessEntry {principal} (principal role propagation)",
    )
    ctx.on_cleanup(lambda: c.delete_access_entry(clusterName=cluster, principalArn=principal))
    before = c.list_associated_access_policies(clusterName=cluster, principalArn=principal)[
        "associatedAccessPolicies"
    ]
    assert before == [], f"expected no associated policies before association, got {before}"

    assoc = c.associate_access_policy(
        clusterName=cluster,
        principalArn=principal,
        policyArn=VIEW_POLICY_ARN,
        accessScope={"type": "cluster"},
    )
    assert assoc["clusterName"] == cluster, assoc
    assert assoc["principalArn"] == principal, assoc
    assert assoc["associatedAccessPolicy"]["policyArn"] == VIEW_POLICY_ARN, assoc
    assert assoc["associatedAccessPolicy"]["accessScope"]["type"] == "cluster", assoc

    listed = c.list_associated_access_policies(clusterName=cluster, principalArn=principal)[
        "associatedAccessPolicies"
    ]
    assert [p["policyArn"] for p in listed] == [VIEW_POLICY_ARN], listed

    c.disassociate_access_policy(clusterName=cluster, principalArn=principal, policyArn=VIEW_POLICY_ARN)
    after = c.list_associated_access_policies(clusterName=cluster, principalArn=principal)[
        "associatedAccessPolicies"
    ]
    assert after == [], after
    # Losing its policy must not delete the access entry itself.
    still = c.describe_access_entry(clusterName=cluster, principalArn=principal)["accessEntry"]
    assert still["principalArn"] == principal, still



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
