"""cluster-update-serialization."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
CONFLICT_CODES = {"ResourceInUseException", "InvalidRequestException", "InvalidStateException"}


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

def _create_cluster_with_retry(c, params, timeout_s=90, interval_s=5):
    """CreateCluster with a just-created role can be rejected until the role's
    trust policy propagates; retry on that specific rejection instead of
    guessing a fixed propagation delay up front."""
    deadline = time.time() + timeout_s
    while True:
        try:
            c.create_cluster(**params)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            role_not_ready = code == "InvalidParameterException" and "role" in message.lower()
            if role_not_ready and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _delete_cluster_with_retry(c, name, timeout_s=900, interval_s=15):
    """DeleteCluster can be transiently refused with ResourceInUseException even after every update
    this check started has reached a terminal status — the update-in-flight view lags the update's
    own terminal status. Retry the delete itself, not just poll status, or ctx.on_cleanup swallows
    the exception and the cluster leaks."""
    deadline = time.time() + timeout_s
    while True:
        try:
            c.delete_cluster(name=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.time() >= deadline:
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
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")

def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise

def _cluster_params(ctx, name, version=None):
    params = dict(
        name=name,
        roleArn=_ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]),
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
    return params

def _provision_cluster(ctx, version=None):
    """Create a cluster owned solely by this check and wait for ACTIVE."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-cl-")
    _create_cluster_with_retry(c, _cluster_params(ctx, name, version=version))
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(c, name))
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

def _supported_versions(c, standard_only=True):
    try:
        resp = c.describe_cluster_versions()
    except Exception:
        return []
    out = []
    for item in resp.get("clusterVersions", []):
        ver = item.get("clusterVersion")
        status = str(item.get("clusterVersionStatus", "")).lower().replace("_", "-")
        if not ver or "unsupported" in status:
            continue
        if standard_only and status and "standard" not in status:
            continue
        out.append(ver)
    return sorted(set(out), key=_vtuple)

def _upgradable_version_pair(c):
    for standard_only in (True, False):
        versions = _supported_versions(c, standard_only=standard_only)
        if len(versions) >= 2:
            return versions[0], versions[1]
    return None, None

def _next_minor(version: str):
    parts = version.split(".")
    if len(parts) >= 2 and parts[1].isdigit():
        return f"{parts[0]}.{int(parts[1]) + 1}"
    return version

CHECK = "cluster-update-serialization"
GROUP = 'ordering'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a LoggingUpdate is InProgress, a second UpdateClusterConfig fails with ResourceInUseException
    and UpdateClusterVersion is refused, both with exact messages, and ListUpdates shows only the first
    update; once it ends Successful a new update starts.
    """
    c = ctx.client("eks")
    create_version, upgrade_target = _upgradable_version_pair(c)
    cluster = _provision_cluster(ctx, version=create_version)

    assert cluster in c.list_clusters()["clusters"], "new cluster missing from ListClusters"

    first = c.update_cluster_config(
        name=cluster,
        logging={"clusterLogging": [{"types": ["api", "audit"], "enabled": True}]},
    )["update"]
    update_id = first["id"]
    assert first["status"] == "InProgress", f"expected InProgress, got {first['status']}"
    assert first["type"] == "LoggingUpdate", f"expected LoggingUpdate, got {first['type']}"

    # a second config update on the same cluster is refused outright.
    second_code, second_msg = _error(
        lambda: c.update_cluster_config(
            name=cluster,
            logging={
                "clusterLogging": [
                    {"types": ["authenticator", "controllerManager", "scheduler"], "enabled": True}
                ]
            },
        )
    )
    assert second_code == "ResourceInUseException", (
        f"a second UpdateClusterConfig while an update is InProgress must be rejected "
        f"with ResourceInUseException, got {second_code}"
    )
    expected = f"Cannot LoggingUpdate because cluster {cluster} currently has update {update_id} in progress"
    assert second_msg == expected, f"expected message {expected!r}, got {second_msg!r}"

    # so is a version upgrade to a genuinely valid target.
    current = c.describe_cluster(name=cluster)["cluster"]["version"]
    target = upgrade_target or _next_minor(current)
    version_code, version_msg = _error(lambda: c.update_cluster_version(name=cluster, version=target))
    assert version_code in CONFLICT_CODES, (
        f"UpdateClusterVersion (to {target}) while an update is InProgress must be "
        f"rejected with a conflict error, got {version_code}"
    )
    if version_code == "ResourceInUseException":
        expected = f"Cannot VersionUpdate because cluster {cluster} currently has update {update_id} in progress"
        assert version_msg == expected, f"expected message {expected!r}, got {version_msg!r}"

    # the rejected calls left no trace: exactly one update exists
    desc = c.describe_update(name=cluster, updateId=update_id)["update"]
    assert desc["id"] == update_id, f"DescribeUpdate returned {desc['id']}"
    assert desc["status"] in {"InProgress", "Successful"}, f"unexpected status {desc['status']}"
    ids = c.list_updates(name=cluster)["updateIds"]
    assert ids == [update_id], f"rejected updates must not be recorded; ListUpdates={ids}"

    # the refusal is ordering, not permanent: once the in-flight update
    # finishes, the identical second update is accepted and recorded alongside
    # the first — proving the block was the InProgress state, not a defect
    # that would have rejected it regardless.
    first_final = _wait_for(
        lambda: c.describe_update(name=cluster, updateId=update_id)["update"]["status"],
        lambda s: s in {"Successful", "Failed", "Cancelled"},
        timeout_s=900,
        interval_s=15,
        desc=f"update {update_id} to leave InProgress",
    )
    assert first_final == "Successful", (
        f"logging update {update_id} finished as {first_final}, expected Successful"
    )

    second = c.update_cluster_config(
        name=cluster,
        logging={
            "clusterLogging": [
                {"types": ["authenticator", "controllerManager", "scheduler"], "enabled": True}
            ]
        },
    )["update"]
    assert second["status"] == "InProgress", f"expected InProgress, got {second['status']}"
    ids_after = set(c.list_updates(name=cluster)["updateIds"])
    assert {update_id, second["id"]} <= ids_after, (
        f"second update not recorded once the block cleared; ListUpdates={ids_after}"
    )

    # drain the second update so cleanup's DeleteCluster is not itself refused
    # with ResourceInUseException by an update this check started.
    _wait_for(
        lambda: c.describe_update(name=cluster, updateId=second["id"])["update"]["status"],
        lambda s: s in {"Successful", "Failed", "Cancelled"},
        timeout_s=900,
        interval_s=15,
        desc=f"update {second['id']} to finish before cleanup",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
