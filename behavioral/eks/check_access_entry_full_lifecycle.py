"""access-entry-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-entry-full-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NOT_FOUND = "The requested resource does not exist."
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _expect_error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


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
            Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _delete_access_entry_if_present(c, cluster, principal):
    """Teardown: the check deletes the entry itself on the happy path, so an absent entry is fine."""
    try:
        c.delete_access_entry(clusterName=cluster, principalArn=principal)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_role_propagation(fn, timeout_s=120, interval_s=6, desc=""):
    """Retry fn() through the window where EKS still rejects a just-created IAM role as
    unrecognized (InvalidParameterException) because IAM is eventually consistent. Any other
    error, or a timeout, raises immediately - this bounds the wait instead of guessing a sleep."""
    deadline = time.time() + timeout_s
    last_exc = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{desc} kept failing on IAM propagation lag after {timeout_s}s: {last_exc}")


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept. Unlike CLUSTER_ROLE
    (a fixed, deliberately reused name), this role's name is unique per run, so it must be
    torn down here or every run leaks a new one."""
    name = ctx.unique_name(PREFIX + label)
    arn = _ensure_role(ctx, name, "ec2.amazonaws.com")
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=name))
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
        desc=f"create_cluster {name}",
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An access entry describes and lists as created, UpdateAccessEntry changes its groups and username
    under the same ARN, and after DeleteAccessEntry it is unlisted while Describe and Update fail with
    ResourceNotFoundException "The requested resource does not exist.".
    """
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-ae-")
    principal = _principal_role(ctx)

    created = _retry_role_propagation(
        lambda: c.create_access_entry(
            clusterName=cluster,
            principalArn=principal,
            kubernetesGroups=["sim2real-viewers"],
            username="sim2real-user",
            type="STANDARD",
            tags={"sim2real": "1"},
        )["accessEntry"],
        desc="create_access_entry",
    )
    ctx.on_cleanup(lambda: _delete_access_entry_if_present(c, cluster, principal))
    assert created["principalArn"] == principal, created
    assert created["clusterName"] == cluster, created
    assert created["kubernetesGroups"] == ["sim2real-viewers"], created
    assert created["username"] == "sim2real-user", created
    assert created["type"] == "STANDARD", created
    assert created["accessEntryArn"], created

    described = c.describe_access_entry(clusterName=cluster, principalArn=principal)["accessEntry"]
    assert described["accessEntryArn"] == created["accessEntryArn"], described
    assert described["kubernetesGroups"] == ["sim2real-viewers"], described

    listed = c.list_access_entries(clusterName=cluster)["accessEntries"]
    assert principal in listed, f"expected {principal} in access entries, got {listed}"

    c.update_access_entry(
        clusterName=cluster,
        principalArn=principal,
        kubernetesGroups=["sim2real-admins"],
        username="sim2real-user-2",
    )
    updated = c.describe_access_entry(clusterName=cluster, principalArn=principal)["accessEntry"]
    assert updated["kubernetesGroups"] == ["sim2real-admins"], updated
    assert updated["username"] == "sim2real-user-2", updated
    # An in-place update must mutate, not re-create: identity is preserved.
    assert updated["accessEntryArn"] == created["accessEntryArn"], updated

    c.delete_access_entry(clusterName=cluster, principalArn=principal)
    describe_code = _expect_error(
        lambda: c.describe_access_entry(clusterName=cluster, principalArn=principal)
    )
    assert describe_code == ("ResourceNotFoundException", _NOT_FOUND), (
        f"expected ResourceNotFoundException describing a deleted access entry, got {describe_code}"
    )
    listed_after_delete = c.list_access_entries(clusterName=cluster)["accessEntries"]
    assert principal not in listed_after_delete, (
        f"deleted principal {principal} still present in access entries {listed_after_delete}"
    )

    # The delete must make the id unusable, not just absent from a read - a mutation
    # against the dead id has to fail the same specific way.
    update_code = _expect_error(
        lambda: c.update_access_entry(
            clusterName=cluster, principalArn=principal, username="sim2real-user-3"
        )
    )
    assert update_code == ("ResourceNotFoundException", _NOT_FOUND), (
        f"expected ResourceNotFoundException updating a deleted access entry, got {update_code}"
    )


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
