"""eks-concurrent-update-cluster-config-admits-exactly-one-update."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-concurrent-update-cluster-config-admits-exactly-one-update"
GROUP = 'concurrency'
SERVICES = ['eks']

# Shared cluster adopted under a deterministic name; only the creating run registers teardown.
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
_UPDATE_TIMEOUT_S = 900


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for(fn, pred, *, timeout_s, interval_s, desc, ctx=None):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{desc}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _trust(service):
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


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create-or-reuse the fixture's IAM role; return (arn, freshly_created)."""
    iam = ctx.client("iam")
    created = False
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="sim2real ga-depth eks shared fixture",
        )["Role"]["Arn"]
        created = True
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn, created


def _fixture_subnets(ctx):
    """Default-VPC subnets in EKS-supported AZs that actually offer the node instance type."""
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_NODE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered and z["ZoneId"] not in _BAD_AZS
    }
    assert usable, (
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            f"EKS needs subnets in >=2 supported AZs; the run's shared network offers {sorted(by_az)!r}"
        )
    return [by_az[az] for az in sorted(by_az)][:3]


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_with_retry(fn, desc):
    """Issue a delete AWS can transiently refuse, retrying it within a bounded budget.

    DeleteCluster can be refused with ResourceInUseException ("update in progress") even when
    ListUpdates is empty, so the delete itself is retried rather than only polled.
    """
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with ResourceInUseException after "
                    f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _teardown_cluster(c, name):
    """Drain dependents then delete the control plane, polling it to actually gone."""
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _delete_with_retry(
                lambda ng=ng: c.delete_nodegroup(clusterName=name, nodegroupName=ng),
                f"delete nodegroup {ng}",
            )
            _wait_for(
                lambda ng=ng: _nodegroup_status(c, name, ng),
                lambda s: s == "GONE",
                timeout_s=_NODEGROUP_TIMEOUT_S,
                interval_s=2,
                desc=f"nodegroup {ng} deleted",
            )
        for addon in c.list_addons(clusterName=name).get("addons", []):
            try:
                c.delete_addon(clusterName=name, addonName=addon, preserve=False)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        for fp in c.list_fargate_profiles(clusterName=name).get("fargateProfileNames", []):
            c.delete_fargate_profile(clusterName=name, fargateProfileName=fp)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: _delete_eks_cluster_retrying(c, name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=2,
        desc=f"cluster {name} fully deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Return the shared ACTIVE cluster; teardown only if this call created it."""
    c = ctx.client("eks")
    role_arn, role_created = _ensure_role(
        ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]
    )
    subnet_ids = _fixture_subnets(ctx)
    cluster_config = dict(
        name=_SHARED_CLUSTER,
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
        tags=dict(_FIXTURE_TAGS),
    )
    # A role this call just created is not yet reliably assumable by EKS -- IAM is eventually
    # consistent and EKS validates roleArn synchronously. Bound the retry to the freshly-created
    # case only, on a deadline, rather than blindly sleeping before the first attempt.
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:
        try:
            c.create_cluster(**cluster_config)
            ctx.on_cleanup(lambda: _teardown_cluster(c, _SHARED_CLUSTER))
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceInUseException":
                break
            if role_created and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if role_created and _budget_spent(ctx):
                raise TimeoutError(f"CreateCluster {_SHARED_CLUSTER} past IAM propagation: the run budget ended first; not graded") from exc
            raise
    cluster = _wait_for(
        lambda: c.describe_cluster(name=_SHARED_CLUSTER)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _CLUSTER_TIMEOUT_S),
        interval_s=2,
        desc=f"cluster {_SHARED_CLUSTER} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"shared cluster landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    return cluster


def _update_ids(c, cluster):
    """Every update id the cluster has recorded, fully paginated for the baseline diff."""
    ids = set()
    token = None
    while True:
        kwargs = {"name": cluster, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = c.list_updates(**kwargs)
        ids.update(page.get("updateIds", []))
        token = page.get("nextToken")
        if not token:
            return ids


def _enabled_log_types(c, cluster):
    """The set of control-plane log types the cluster currently has ENABLED."""
    logging = c.describe_cluster(name=cluster)["cluster"].get("logging", {})
    enabled = set()
    for entry in logging.get("clusterLogging", []):
        if entry.get("enabled"):
            enabled.update(entry.get("types", []))
    return enabled


def _restore_logging(c, cluster):
    """Put the shared cluster's control-plane logging back to all-disabled.

    Waits for the cluster to leave UPDATING first, since UpdateClusterConfig is refused meanwhile.
    """
    _wait_for(
        lambda: _cluster_status(c, cluster),
        lambda s: s in ("ACTIVE", "GONE"),
        timeout_s=_UPDATE_TIMEOUT_S,
        interval_s=2,
        desc=f"cluster {cluster} idle before restoring logging",
    )
    if _cluster_status(c, cluster) != "ACTIVE":
        return
    if not _enabled_log_types(c, cluster):
        return
    c.update_cluster_config(
        name=cluster,
        logging={"clusterLogging": [
            {"types": ["api", "audit", "authenticator", "controllerManager", "scheduler"],
             "enabled": False}]},
    )


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two simultaneous UpdateClusterConfig logging updates, exactly one is admitted, the other
    gets ResourceInUseException, ListUpdates gains one id, and only the winner's logging is live.

    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html
    """
    # The winner is discovered from the outcomes, never assumed, so thread scheduling cannot matter.
    c = ctx.client("eks")
    _adopt_or_create_cluster(ctx)

    # A logging update is refused while another is in flight, so start from a settled cluster.
    _wait_for(
        lambda: _cluster_status(c, _SHARED_CLUSTER),
        lambda s: s == "ACTIVE",
        ctx=ctx,
        timeout_s=_budget_s(ctx, _UPDATE_TIMEOUT_S),
        interval_s=2,
        desc=f"cluster {_SHARED_CLUSTER} has no update in flight",
    )
    baseline_ids = _update_ids(c, _SHARED_CLUSTER)
    wanted = {"api": {"api"}, "audit": {"audit"}}

    # Both calls leave together, so neither can arrive after the other's update has finished.
    gate = threading.Barrier(2)

    def _attempt(log_type):
        gate.wait(timeout=30)
        try:
            return log_type, c.update_cluster_config(
                name=_SHARED_CLUSTER,
                logging={"clusterLogging": [{"types": [log_type], "enabled": True}]},
            )["update"], None
        except ClientError as exc:
            return log_type, None, exc.response["Error"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_attempt, ["api", "audit"]))
    ctx.on_cleanup(lambda: _restore_logging(c, _SHARED_CLUSTER))

    accepted = [(lt, up) for lt, up, code in outcomes if up is not None]
    failure_codes = [err["Code"] for _, up, err in outcomes if up is None]

    assert len(accepted) == 1, (
        f"{len(accepted)} of two simultaneous UpdateClusterConfig calls were admitted; EKS must "
        f"serialise them: "
        f"{[(lt, (up or {}).get('id'), code) for lt, up, code in outcomes]!r}"
    )
    winner_type, winner = accepted[0]
    assert winner["status"] == "InProgress", (
        f"the admitted update reported {winner['status']!r} rather than InProgress: {winner!r}"
    )
    assert winner["type"] == "LoggingUpdate", f"{winner!r}"

    assert set(failure_codes) == {"ResourceInUseException"}, (
        f"the rejected calls reported {failure_codes!r}; a concurrent UpdateClusterConfig must be "
        f"refused with ResourceInUseException"
    )
    expected = (
        f"Cannot LoggingUpdate because cluster {_SHARED_CLUSTER} currently has update "
        f"{winner['id']} in progress"
    )
    failure_messages = [err.get("Message") for _, up, err in outcomes if up is None]
    assert failure_messages == [expected], f"expected the refusal {expected!r}, got {failure_messages!r}"

    # A refused update must not be journalled.
    new_ids = _update_ids(c, _SHARED_CLUSTER) - baseline_ids
    assert sorted(new_ids) == [winner["id"]], (
        f"ListUpdates gained {sorted(new_ids)!r} but only {winner['id']!r} was accepted -- a "
        f"refused update must not be journalled"
    )

    final = _wait_for(
        lambda: c.describe_update(name=_SHARED_CLUSTER, updateId=winner["id"])["update"],
        lambda u: u["status"] != "InProgress",
        ctx=ctx,
        timeout_s=_budget_s(ctx, _UPDATE_TIMEOUT_S),
        interval_s=2,
        desc=f"update {winner['id']} terminal",
    )
    assert final["status"] == "Successful", f"{final!r}"
    assert final["type"] == "LoggingUpdate", f"{final!r}"

    # The loser's configuration must leave no trace, so the refusal is real rather than cosmetic.
    live = _wait_for(
        lambda: _enabled_log_types(c, _SHARED_CLUSTER),
        lambda types: types == wanted[winner_type],
        ctx=ctx,
        timeout_s=_budget_s(ctx, _UPDATE_TIMEOUT_S),
        interval_s=2,
        desc=f"cluster logging settles on {sorted(wanted[winner_type])!r}",
    )
    assert live == wanted[winner_type], (
        f"the cluster ended up with logging {sorted(live)!r} enabled; the admitted update asked "
        f"for {sorted(wanted[winner_type])!r} and the refused one for "
        f"{sorted(wanted['audit' if winner_type == 'api' else 'api'])!r}"
    )



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=2.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
