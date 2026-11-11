"""addon-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "addon-full-lifecycle"
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


def _addon_version_key(version):
    """Sort key for addon versions like ``v1.3.7-eksbuild.2`` (newest = largest)."""
    core, _, build = version.lstrip("v").partition("-eksbuild.")
    nums = tuple(int(p) for p in core.split(".") if p.isdigit())
    return (nums, int(build) if build.isdigit() else 0)


def _gone(fn):
    """True once fn() answers ResourceNotFoundException, False while it succeeds (for gone-polling)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return True
    return False


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An addon goes CREATING to ACTIVE, a duplicate CreateAddon fails with "Addon already exists." and leaves
    it unchanged, an update to another catalog version (when one exists) ends Successful in place, and after
    delete Describe fails with ResourceNotFoundException and its exact message and ListAddons omits it.
    """
    c = ctx.client("eks")
    name = _active_cluster(ctx, c, "eks-add-")
    version = c.describe_cluster(name=name)["cluster"]["version"]

    catalog = c.describe_addon_versions(addonName=ADDON_NAME, kubernetesVersion=version)["addons"]
    assert catalog and catalog[0]["addonName"] == ADDON_NAME, catalog
    versions = sorted(
        (v["addonVersion"] for v in catalog[0]["addonVersions"]),
        key=_addon_version_key,
        reverse=True,
    )
    assert versions, catalog
    target = versions[0]
    start = versions[1] if len(versions) > 1 else versions[0]

    schema = c.describe_addon_configuration(addonName=ADDON_NAME, addonVersion=target)
    assert schema["addonName"] == ADDON_NAME, schema
    assert schema["addonVersion"] == target, schema
    assert schema["configurationSchema"], schema

    created = c.create_addon(
        clusterName=name,
        addonName=ADDON_NAME,
        addonVersion=start,
        resolveConflicts="OVERWRITE",
        tags={"sim2real": "1"},
    )["addon"]
    ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_addon(clusterName=name, addonName=ADDON_NAME)))
    assert created["status"] == "CREATING", created
    assert created["addonName"] == ADDON_NAME, created
    assert created["clusterName"] == name, created
    assert ADDON_NAME in c.list_addons(clusterName=name)["addons"], (
        f"expected {ADDON_NAME!r} in list_addons after create, got "
        f"{c.list_addons(clusterName=name)['addons']!r}"
    )

    active = _wait_for(
        lambda: c.describe_addon(clusterName=name, addonName=ADDON_NAME)["addon"],
        lambda a: a["status"] in ("ACTIVE", "CREATE_FAILED", "UPDATE_FAILED"),
        timeout_s=420, interval_s=10, desc=f"addon {ADDON_NAME} ACTIVE",
    )
    assert active["status"] == "ACTIVE", f"addon landed in {active['status']!r}"
    assert active["addonVersion"] == start, active
    assert active["addonArn"], active

    dup_code, dup_message = _error(lambda: c.create_addon(clusterName=name, addonName=ADDON_NAME))
    assert dup_code == "ResourceInUseException", f"expected ResourceInUseException, got {dup_code!r}"
    assert dup_message == "Addon already exists.", dup_message

    # Effect absent: the rejected duplicate create left the existing addon untouched.
    unaffected = c.describe_addon(clusterName=name, addonName=ADDON_NAME)["addon"]
    assert unaffected["status"] == "ACTIVE", f"expected ACTIVE after rejected duplicate create, got {unaffected['status']!r}"
    assert unaffected["addonVersion"] == start, (
        f"expected addonVersion {start!r} unchanged after rejected duplicate create, got {unaffected['addonVersion']!r}"
    )
    assert unaffected["addonArn"] == active["addonArn"], (
        f"expected addonArn {active['addonArn']!r} unchanged after rejected duplicate create, got {unaffected['addonArn']!r}"
    )

    if target != start:
        update = c.update_addon(
            clusterName=name,
            addonName=ADDON_NAME,
            addonVersion=target,
            resolveConflicts="OVERWRITE",
        )["update"]
        assert update["status"] == "InProgress", update
        assert update["type"] == "AddonUpdate", update
        seen = c.describe_update(name=name, addonName=ADDON_NAME, updateId=update["id"])["update"]
        assert seen["id"] == update["id"], seen
        terminal = _wait_for(
            lambda: c.describe_update(name=name, addonName=ADDON_NAME, updateId=update["id"])["update"],
            lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
            timeout_s=300, interval_s=10, desc=f"update {update['id']} terminal",
        )
        assert terminal["status"] == "Successful", terminal
        updated = _wait_for(
            lambda: c.describe_addon(clusterName=name, addonName=ADDON_NAME)["addon"],
            lambda a: a["status"] == "ACTIVE",
            timeout_s=240, interval_s=10, desc=f"addon {ADDON_NAME} updated ACTIVE",
        )
        assert updated["addonVersion"] == target, updated
        assert updated["addonArn"] == active["addonArn"], updated

    c.delete_addon(clusterName=name, addonName=ADDON_NAME)
    _wait_for(
        lambda: _gone(lambda: c.describe_addon(clusterName=name, addonName=ADDON_NAME)),
        lambda gone: gone,
        timeout_s=300, interval_s=10, desc=f"addon {ADDON_NAME} gone",
    )
    post_delete_code, post_delete_message = _error(lambda: c.describe_addon(clusterName=name, addonName=ADDON_NAME))
    assert post_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from describe_addon after delete, got {post_delete_code!r}"
    )
    assert post_delete_message == "The requested resource does not exist.", post_delete_message
    post_delete_list = c.list_addons(clusterName=name)["addons"]
    assert ADDON_NAME not in post_delete_list, (
        f"expected {ADDON_NAME!r} absent from list_addons after delete, got {post_delete_list!r}"
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
