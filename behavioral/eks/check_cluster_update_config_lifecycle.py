"""cluster-update-config-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-update-config-lifecycle"
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


def _create_cluster_with_retry(c, name, role_arn, subnet_ids, attempts=8, interval_s=10):
    """CreateCluster, tolerating IAM propagation lag on a freshly created role.

    A brand-new role is not yet visible everywhere EKS validates it; retry the identical
    call on a bounded schedule rather than sleeping blindly before the first attempt.
    """
    last_exc = None
    for _ in range(attempts):
        try:
            return c.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                tags={"sim2real": "1"},
            )
        except ClientError as exc:  # fresh IAM role can take a few seconds to propagate
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"create_cluster kept failing (likely IAM role propagation lag): {last_exc}")


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
    _create_cluster_with_retry(c, name, role_arn, _subnet_ids(ctx))
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateClusterConfig enabling api and audit logs returns an InProgress LoggingUpdate that DescribeUpdate
    and ListUpdates show while the cluster reads UPDATING; it ends Successful with both log types enabled.
    """
    c = ctx.client("eks")
    name = _active_cluster(ctx, c, "eks-cfg-")
    before = set(c.list_updates(name=name)["updateIds"])

    update = c.update_cluster_config(
        name=name,
        logging={"clusterLogging": [{"types": ["api", "audit"], "enabled": True}]},
    )["update"]
    update_id = update["id"]
    assert update["status"] == "InProgress", update
    assert update["type"] == "LoggingUpdate", update

    # While the record is open the cluster itself reports UPDATING — poll rather than
    # accept ACTIVE as an alternative, or a target that never flips the status at all
    # would pass this line unchallenged.
    interim = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] == "UPDATING",
        timeout_s=30, interval_s=3,
        desc=f"cluster {name} status flips to UPDATING while update {update_id} is open",
    )
    assert interim["status"] == "UPDATING", interim["status"]

    seen = c.describe_update(name=name, updateId=update_id)["update"]
    assert seen["id"] == update_id, seen
    assert seen["type"] == "LoggingUpdate", seen

    ids = set(c.list_updates(name=name)["updateIds"])
    assert update_id in ids, ids
    assert ids > before, (ids, before)

    terminal = _wait_for(
        lambda: c.describe_update(name=name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=420, interval_s=10, desc=f"update {update_id} terminal",
    )
    assert terminal["status"] == "Successful", terminal

    after = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] == "ACTIVE",
        timeout_s=300, interval_s=10, desc=f"cluster {name} back to ACTIVE",
    )
    enabled = {t for entry in after["logging"]["clusterLogging"] if entry["enabled"] for t in entry["types"]}
    assert {"api", "audit"} <= enabled, after["logging"]


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
