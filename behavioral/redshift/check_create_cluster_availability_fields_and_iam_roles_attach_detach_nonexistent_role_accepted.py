"""create-cluster-availability-fields-and-iam-roles-attach-detach-nonexistent-role-accepted."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "create-cluster-availability-fields-and-iam-roles-attach-detach-nonexistent-role-accepted"
)
GROUP = "cluster-lifecycle"
SERVICES = ["redshift"]

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"

_REDSHIFT_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "redshift.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s, interval_s=15, what="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _describe_cluster(rs, cluster_id):
    resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _cluster_status(rs, cluster_id):
    try:
        cluster = _describe_cluster(rs, cluster_id)
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    return cluster["ClusterStatus"] if cluster else None


def _wait_for_cluster_available(ctx, rs, cluster_id, timeout_s=660):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=2,
        what=f"cluster {cluster_id} to reach a terminal creation state",
        ctx=ctx,
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _wait_for_cluster_gone(rs, cluster_id, deadline):
    """Poll DescribeClusters every 2 s until it answers ClusterNotFound; raise at *deadline*."""
    while True:
        try:
            clusters = rs.describe_clusters(ClusterIdentifier=cluster_id).get("Clusters", [])
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            raise
        if time.monotonic() >= deadline:
            status = clusters[0].get("ClusterStatus") if clusters else None
            raise TimeoutError(f"cluster {cluster_id} still listed ({status!r}) at the teardown deadline")
        time.sleep(2)


def _delete_cluster(rs, cluster_id):
    """Teardown: DeleteCluster, retrying InvalidClusterState (creating, modifying or deleting) every
    2 s, then wait for ClusterNotFound, since the delete is asynchronous. One deadline bounds both."""
    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_for_cluster_gone(rs, cluster_id, deadline)


def _create_role(iam, name, scenario):
    arn = _retrying(lambda: iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_REDSHIFT_TRUST,
        Description=f"sim2real-behav redshift {scenario}",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    ))["Role"]["Arn"]
    return arn


def _delete_role(iam, name):
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _iam_role_arns(cluster):
    return {r["IamRoleArn"] for r in cluster.get("IamRoles", [])}


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An available cluster reports ClusterAvailabilityStatus and AZ relocation as Terraform
    expects; ModifyClusterIamRoles attaches/detaches roles and accepts a nonexistent role ARN,
    which settles "in-sync".
    """
    rs = ctx.client("redshift")
    iam = ctx.client("iam")
    cluster_id = ctx.unique_name("sim2real-behav-rs-iamroles-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    _wait_for_cluster_available(ctx, rs, cluster_id)

    cluster = _describe_cluster(rs, cluster_id)
    assert cluster["ClusterAvailabilityStatus"] == "Available", (
        f"an available cluster must report ClusterAvailabilityStatus='Available', "
        f"got {cluster.get('ClusterAvailabilityStatus')!r}"
    )
    # AWS defaults AZ relocation to 'enabled' for an eligible node type with no relocation request.
    assert cluster["AvailabilityZoneRelocationStatus"] == "enabled", (
        f"expected AvailabilityZoneRelocationStatus='enabled' by default, "
        f"got {cluster.get('AvailabilityZoneRelocationStatus')!r}"
    )
    assert _iam_role_arns(cluster) == set(), (
        f"a freshly created cluster with no IamRoles param must report none attached, "
        f"got {cluster.get('IamRoles')!r}"
    )

    role_name = ctx.unique_name("sim2real-behav-rs-iamroles-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = _create_role(iam, role_name, CHECK)

    # IAM propagation: a just-created role is rejected with InvalidIamRoleFault (undeclared in the
    # model) until Redshift can see it, so retry the attach, bounded.
    deadline = time.monotonic() + _budget_s(ctx, 180)
    while True:
        try:
            _retrying(lambda: rs.modify_cluster_iam_roles(
                ClusterIdentifier=cluster_id, AddIamRoles=[role_arn]
            ))
            break
        except ClientError as exc:
            if _code_of(exc) != "InvalidIamRoleFault":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"AddIamRoles on {cluster_id} accepted: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    _wait_for_cluster_available(ctx, rs, cluster_id)

    attached = _describe_cluster(rs, cluster_id)
    assert _iam_role_arns(attached) == {role_arn}, (
        f"expected IamRoles to contain exactly {role_arn!r} after AddIamRoles, "
        f"got {attached.get('IamRoles')!r}"
    )

    # ModifyClusterIamRoles does not check that the role exists: a well-formed ARN for a role never
    # created settles at "in-sync"; existence is checked only when the cluster assumes the role.
    bogus_role_arn = f"{role_arn}-does-not-exist"
    accepted = rs.modify_cluster_iam_roles(ClusterIdentifier=cluster_id, AddIamRoles=[bogus_role_arn])
    assert accepted["Cluster"]["ClusterStatus"] != "available", (
        f"attaching a role must put the cluster into a transient modifying state, "
        f"got {accepted['Cluster']['ClusterStatus']!r}"
    )
    _wait_for_cluster_available(ctx, rs, cluster_id)
    with_bogus = _describe_cluster(rs, cluster_id)
    assert _iam_role_arns(with_bogus) == {role_arn, bogus_role_arn}, (
        f"expected both the real and the nonexistent role ARN to be reported attached, "
        f"got {with_bogus.get('IamRoles')!r}"
    )
    bogus_entry = next(r for r in with_bogus["IamRoles"] if r["IamRoleArn"] == bogus_role_arn)
    assert bogus_entry["ApplyStatus"] == "in-sync", (
        f"a nonexistent role must still settle to 'in-sync' (AWS defers the existence check to "
        f"first use), got {bogus_entry['ApplyStatus']!r}"
    )

    rs.modify_cluster_iam_roles(
        ClusterIdentifier=cluster_id, RemoveIamRoles=[role_arn, bogus_role_arn]
    )
    _wait_for_cluster_available(ctx, rs, cluster_id)
    detached = _describe_cluster(rs, cluster_id)
    assert _iam_role_arns(detached) == set(), (
        f"expected IamRoles empty after RemoveIamRoles, got {detached.get('IamRoles')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
