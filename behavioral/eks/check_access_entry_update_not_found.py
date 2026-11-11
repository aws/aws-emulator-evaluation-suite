"""access-entry-update-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-entry-update-not-found"
GROUP = 'overly-permissive'
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
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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


def _retry_role_propagation(fn, timeout_s=90, interval_s=10):
    """IAM is eventually consistent: a role this check just created may not yet resolve
    when EKS validates it synchronously - as a cluster roleArn ("...invalid: role ...")
    or as an access-entry principalArn ("...invalid principal"). Retry the dependent call
    itself on that real signal up to a deadline, instead of guessing a fixed delay.
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            msg = err.get("Message", "").lower()
            transient = "role" in msg or "principal" in msg
            if err["Code"] != "InvalidParameterException" or not transient or time.time() >= deadline:
                raise
            time.sleep(interval_s)


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    return _ensure_role(ctx, ctx.unique_name(PREFIX + label), "ec2.amazonaws.com")


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs, preferring the shared network but
    falling back to any VPC's subnets (a freshly provisioned account may have no default
    VPC) - grouped by VPC so the fallback never mixes subnets across VPCs, which EKS
    would reject.
    """
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_vpc: dict[str, dict[str, str]] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_vpc.setdefault(sn["VpcId"], {}).setdefault(az, sn["SubnetId"])
    by_az = max(by_vpc.values(), key=len, default={})
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs in one VPC, found {len(by_az)}")
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
        )
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an ACTIVE cluster, update/describe/associate/delete of a real access entry succeed, while the same
    four calls on a principal with no entry fail with ResourceNotFoundException and UpdateAccessEntry
    creates no entry.
    """
    c = ctx.client("eks")
    name = _active_cluster(ctx, c, "eks-aenf-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    principal = _principal_role(ctx)
    _retry_role_propagation(
        lambda: c.create_access_entry(clusterName=name, principalArn=principal, type="STANDARD")
    )
    ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_access_entry(clusterName=name, principalArn=principal)))
    assert principal in c.list_access_entries(clusterName=name)["accessEntries"], (
        f"positive control: {principal} missing from list_access_entries right after create"
    )
    c.update_access_entry(clusterName=name, principalArn=principal, kubernetesGroups=["sim2real-viewers"])
    described = c.describe_access_entry(clusterName=name, principalArn=principal)["accessEntry"]
    assert described["kubernetesGroups"] == ["sim2real-viewers"], (
        f"positive control: update_access_entry did not take effect: {described}"
    )
    c.associate_access_policy(
        clusterName=name,
        principalArn=principal,
        policyArn=VIEW_POLICY_ARN,
        accessScope={"type": "cluster"},
    )
    associated = c.list_associated_access_policies(clusterName=name, principalArn=principal)[
        "associatedAccessPolicies"
    ]
    assert any(p["policyArn"] == VIEW_POLICY_ARN for p in associated), (
        f"positive control: associate_access_policy did not attach {VIEW_POLICY_ARN}: {associated}"
    )
    c.delete_access_entry(clusterName=name, principalArn=principal)
    assert principal not in c.list_access_entries(clusterName=name)["accessEntries"], (
        f"positive control: {principal} still listed after delete_access_entry"
    )

    ghost = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('ghost-principal-')}"
    assert ghost not in c.list_access_entries(clusterName=name)["accessEntries"], (
        f"{ghost} unexpectedly present before any access entry was created for it"
    )

    codes = {
        "update": _error(
            lambda: c.update_access_entry(
                clusterName=name, principalArn=ghost, kubernetesGroups=["sim2real-admins"]
            )
        ),
        "describe": _error(
            lambda: c.describe_access_entry(clusterName=name, principalArn=ghost)
        ),
        "delete": _error(
            lambda: c.delete_access_entry(clusterName=name, principalArn=ghost)
        ),
        "associate_policy": _error(
            lambda: c.associate_access_policy(
                clusterName=name,
                principalArn=ghost,
                policyArn=VIEW_POLICY_ARN,
                accessScope={"type": "cluster"},
            )
        ),
    }
    for op, (code, message) in codes.items():
        assert code == "ResourceNotFoundException", (op, code, message)
        assert message == "The requested resource does not exist.", (op, message)
    # The failed update must not have created the entry as a side effect.
    assert ghost not in c.list_access_entries(clusterName=name)["accessEntries"], (
        f"{ghost} appeared in list_access_entries after the rejected update - it upserted"
    )


def _gone_ok(fn):
    """Run a teardown call; a resource the check already deleted in band is done, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
