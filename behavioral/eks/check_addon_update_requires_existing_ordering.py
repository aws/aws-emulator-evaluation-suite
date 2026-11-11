"""addon-update-requires-existing-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NOT_FOUND = "The requested resource does not exist."
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
CONFLICT_CODES = {"ResourceInUseException", "InvalidRequestException", "InvalidStateException"}
# A DaemonSet addon that needs no configuration and no worker nodes.
ADDON = "eks-pod-identity-agent"


def _trust(service: str, extra_actions: tuple[str, ...] = ()) -> str:
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
    """Create-or-reuse an IAM role; return (arn, freshly_created)."""
    iam = ctx.client("iam")
    created = False
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real-managed", "Value": "true"}],
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

_ROLE_PROPAGATION_CODES = {"InvalidParameterException", "AccessDenied", "AccessDeniedException"}

def _create_cluster_with_role_propagation_retry(c, params, role_freshly_created, timeout_s=90, interval_s=10):
    """A just-created IAM role can take a few seconds to become assumable by EKS.
    There is no API to poll for propagation, so retry CreateCluster itself on the
    role-related transient error, bounded by timeout_s; any other error raises immediately."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return c.create_cluster(**params)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if not role_freshly_created or code not in _ROLE_PROPAGATION_CODES or time.time() >= deadline:
                raise
            time.sleep(interval_s)

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

def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")

def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise

def _cluster_params(ctx, name, version=None):
    role_arn, role_created = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    params = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={
            "subnetIds": _subnet_ids(ctx),
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
        tags={"sim2real": "1"},
    )
    if version:
        params["version"] = version
    return params, role_created

def _provision_cluster(ctx, version=None):
    """Create a cluster owned solely by this check and wait for ACTIVE."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-cl-")
    params, role_created = _cluster_params(ctx, name, version=version)
    _create_cluster_with_role_propagation_retry(c, params, role_created)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    status = _cluster_status(c, name)
    assert status == "ACTIVE", f"cluster {name} reached {status}, expected ACTIVE"
    return name

def _vtuple(version: str):
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return (0,)

def _addon_versions(c, addon_name, k8s_version):
    """Ascending addon versions compatible with k8s_version."""
    try:
        resp = c.describe_addon_versions(addonName=addon_name, kubernetesVersion=k8s_version)
    except Exception:
        return []
    out = []
    for addon in resp.get("addons", []):
        for ver in addon.get("addonVersions", []):
            if ver.get("addonVersion"):
                out.append(ver["addonVersion"])
    return sorted(set(out), key=lambda v: _vtuple(v.split("-")[0].lstrip("v")))

def _addon_status(c, cluster, addon):
    try:
        return c.describe_addon(clusterName=cluster, addonName=addon)["addon"]["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise

def _wait_addon_status(c, cluster, addon, targets, timeout_s=300, interval_s=5):
    return _wait_for(
        lambda: _addon_status(c, cluster, addon),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        desc=f"addon {addon} status in {sorted(targets)}",
    )

CHECK = "addon-update-requires-existing-ordering"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] UpdateAddon cannot precede CreateAddon
    (ResourceNotFoundException), and while the addon is still CREATING an update
    MUST be refused; it becomes updatable only after the addon settles."""
    c = ctx.client("eks")
    cluster = _provision_cluster(ctx)
    k8s_version = c.describe_cluster(name=cluster)["cluster"]["version"]
    versions = _addon_versions(c, ADDON, k8s_version)
    assert versions, f"no {ADDON} versions advertised for kubernetes {k8s_version}"
    create_version, target_version = versions[0], versions[-1]

    # (1) update before create -> not found
    pre, pre_msg = _error(
        lambda: c.update_addon(
            clusterName=cluster, addonName=ADDON, addonVersion=target_version,
            resolveConflicts="OVERWRITE",
        )
    )
    assert pre == "ResourceNotFoundException", (
        f"UpdateAddon on an addon that was never created must be "
        f"ResourceNotFoundException, got {pre}"
    )
    assert pre_msg == _NOT_FOUND, f"unexpected UpdateAddon message {pre_msg!r}"

    c.create_addon(
        clusterName=cluster,
        addonName=ADDON,
        addonVersion=create_version,
        resolveConflicts="OVERWRITE",
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_addon(clusterName=cluster, addonName=ADDON)))
    assert ADDON in c.list_addons(clusterName=cluster)["addons"]

    # (2) update while the create is still in flight
    observed = c.describe_addon(clusterName=cluster, addonName=ADDON)["addon"]["status"]
    try:
        c.update_addon(
            clusterName=cluster, addonName=ADDON, addonVersion=target_version,
            resolveConflicts="OVERWRITE",
        )
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        code = message = None
    if observed == "CREATING":
        assert code in CONFLICT_CODES, (
            f"UpdateAddon while the addon is CREATING must be rejected, got {code}"
        )
        if code == "ResourceInUseException":
            expected = f"Addon {ADDON} cannot be updated as it is currently in CREATING state"
            assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        assert code is None, (
            f"addon was already {observed}, so UpdateAddon should have been accepted, got {code}"
        )

    # (3) it settles into a terminal status and is then updatable.
    settled = _wait_addon_status(
        c, cluster, ADDON, {"ACTIVE", "DEGRADED", "CREATE_FAILED"}, timeout_s=300
    )
    assert settled in {"ACTIVE", "DEGRADED"}, f"addon reached {settled}"
    if target_version != create_version:
        upd = c.update_addon(
            clusterName=cluster, addonName=ADDON, addonVersion=target_version,
            resolveConflicts="OVERWRITE",
        )["update"]
        assert upd["status"] == "InProgress", f"expected InProgress, got {upd['status']}"
        assert upd["type"] == "AddonUpdate", f"expected AddonUpdate, got {upd['type']}"

    c.delete_addon(clusterName=cluster, addonName=ADDON)
    gone = _wait_addon_status(c, cluster, ADDON, {"GONE"}, timeout_s=120)
    assert gone == "GONE", f"addon still {gone} after delete"
    post_delete, post_delete_msg = _error(
        lambda: c.update_addon(
            clusterName=cluster, addonName=ADDON, addonVersion=target_version,
            resolveConflicts="OVERWRITE",
        )
    )
    assert post_delete == "ResourceNotFoundException", (
        f"UpdateAddon on a deleted addon must be ResourceNotFoundException, got {post_delete}"
    )
    assert post_delete_msg == _NOT_FOUND, f"unexpected UpdateAddon message {post_delete_msg!r}"


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
