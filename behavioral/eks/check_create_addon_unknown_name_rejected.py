"""create-addon-unknown-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-addon-unknown-name-rejected"
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
    """Create-or-reuse an IAM role and return (arn, freshly_created)."""
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
    return arn, created


def _create_cluster_once_role_is_usable(c, role_created, **kwargs):
    """Call create_cluster, retrying while a just-created IAM role is still propagating.

    IAM is eventually consistent: EKS rejects a brand-new role until it propagates. A fixed sleep
    cannot bound that window, so retry the actual dependent call instead of guessing a duration.
    """
    if not role_created:
        c.create_cluster(**kwargs)
        return
    deadline = time.time() + 60
    while True:
        try:
            c.create_cluster(**kwargs)
            return
        except ClientError:
            if time.time() >= deadline:
                raise
            time.sleep(5)


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
    role_arn, role_created = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    _create_cluster_once_role_is_usable(
        c,
        role_created,
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

ADDON_NAME = "eks-pod-identity-agent"


def _delete_addon_if_present(c, cluster, addon):
    """Teardown: the body deletes the addon itself, so a not-found here means already gone."""
    if not _addon_gone(c, cluster, addon):
        c.delete_addon(clusterName=cluster, addonName=addon)


def _addon_gone(c, cluster, addon):
    """True once DescribeAddon answers ResourceNotFoundException, False while it still resolves."""
    try:
        c.describe_addon(clusterName=cluster, addonName=addon)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAddon with a name outside the EKS catalog fails with InvalidParameterException while a catalog
    addon installs ACTIVE; Describe of that name, an unknown cluster, a bogus schema and Update of an
    uninstalled addon fail with ResourceNotFoundException, all with exact messages.
    """
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-addbad-")
    bogus_addon = "sim2real-not-an-addon"

    # Positive control: CreateAddon must succeed for a real catalog name on this cluster, and the
    # result must be independently visible. Without this, "rejects an unknown addon name" is
    # indistinguishable from "rejects every CreateAddon call". Undone below so the "never installed"
    # assertions further down still hold for ADDON_NAME on this same cluster.
    c.create_addon(clusterName=cluster, addonName=ADDON_NAME)
    ctx.on_cleanup(lambda: _delete_addon_if_present(c, cluster, ADDON_NAME))
    assert ADDON_NAME in c.list_addons(clusterName=cluster)["addons"], (
        f"expected {ADDON_NAME!r} in list_addons after a valid create"
    )
    active = _wait_for(
        lambda: c.describe_addon(clusterName=cluster, addonName=ADDON_NAME)["addon"],
        lambda a: a["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=300, interval_s=10, desc=f"positive-control addon {ADDON_NAME} leaves CREATING",
    )
    assert active["status"] == "ACTIVE", f"positive-control addon landed in {active['status']!r}"

    c.delete_addon(clusterName=cluster, addonName=ADDON_NAME)
    _wait_for(
        lambda: _addon_gone(c, cluster, ADDON_NAME),
        lambda gone: gone,
        timeout_s=300, interval_s=10, desc=f"positive-control addon {ADDON_NAME} gone",
    )
    assert ADDON_NAME not in c.list_addons(clusterName=cluster)["addons"], (
        f"expected {ADDON_NAME!r} absent from list_addons after delete"
    )

    version = c.describe_cluster(name=cluster)["cluster"]["version"]
    not_found = "The requested resource does not exist."

    code, message = _error(lambda: c.create_addon(clusterName=cluster, addonName=bogus_addon))
    assert code == "InvalidParameterException", code
    expected = f"Addon {bogus_addon} specified is not supported in {version} kubernetes version"
    assert message == expected, (message, expected)
    assert bogus_addon not in c.list_addons(clusterName=cluster)["addons"]

    code, message = _error(lambda: c.describe_addon(clusterName=cluster, addonName=bogus_addon))
    assert code == "ResourceNotFoundException", code
    assert message == not_found, message

    absent = ctx.unique_name("absent-clu-")
    code, message = _error(lambda: c.create_addon(clusterName=absent, addonName=ADDON_NAME))
    assert code == "ResourceNotFoundException", code
    assert message == f"No cluster found for name: {absent}.", message

    bogus_version = "v1.0.0-eksbuild.1"
    code, message = _error(
        lambda: c.describe_addon_configuration(addonName=bogus_addon, addonVersion=bogus_version)
    )
    assert code == "ResourceNotFoundException", code
    expected = f"Schema not found for requested addonName=[{bogus_addon}] and addonVersion=[{bogus_version}]"
    assert message == expected, (message, expected)

    # An addon that IS in the catalog but was never installed must still 404.
    code, message = _error(
        lambda: c.update_addon(clusterName=cluster, addonName=ADDON_NAME, resolveConflicts="OVERWRITE")
    )
    assert code == "ResourceNotFoundException", code
    assert message == not_found, message


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
