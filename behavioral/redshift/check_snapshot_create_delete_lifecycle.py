"""snapshot-create-delete-lifecycle."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


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


def _expect_error(fn):
    """Call *fn*, which must fail with an AWS error; return (code, message)."""
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s=600, interval_s=2, what="condition", ctx=None):
    """Poll *probe* until *done*, bounded by *timeout_s* and the check's remaining budget."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"waiting for {what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
PARAM_FAMILY = "redshift-1.0"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
    return _node_type_and_azs(rs, cluster_type)[0]


def _node_type_and_azs(rs, cluster_type="single-node"):
    """(cheapest orderable node type, AZ names that offer it) for *cluster_type*."""
    available = []
    azs_by_type = {}
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
            if nt:
                azs = azs_by_type.setdefault(nt, [])
                for az in opt.get("AvailabilityZones", []):
                    if az.get("Name") and az["Name"] not in azs:
                        azs.append(az["Name"])
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen, sorted(azs_by_type.get(chosen, []))


def _cluster_params(rs, cluster_id, subnet_group_name, **overrides):
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        ClusterSubnetGroupName=subnet_group_name,
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    params.update(overrides)
    return params


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


def _wait_for_cluster_status(rs, cluster_id, target_statuses, timeout_s=600, interval_s=2, ctx=None):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in targets)}",
        ctx=ctx,
    )


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600, ctx=None):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_for_cluster_status(rs, cluster_id, terminal, timeout_s=timeout_s, ctx=ctx)
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_for_cluster_gone(rs, cluster_id, timeout_s=420, interval_s=2):
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} to disappear",
    )


def _delete_cluster(rs, cluster_id):
    """Teardown: a cluster still 'creating' may refuse deletion, so
    retry within a bounded window."""
    deadline = time.time() + 240
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            refusal = exc
        if time.time() >= deadline:
            raise AssertionError(f"delete still refused at the teardown deadline: {refusal!r}")
        time.sleep(3)


def _delete_cluster_and_wait(rs, cluster_id):
    """Teardown: delete the cluster and wait until it is gone, so its subnet group and VPC
    can be deleted after it."""
    _delete_cluster(rs, cluster_id)
    _wait_for_cluster_gone(rs, cluster_id, timeout_s=900, interval_s=3)


def _delete_retrying(fn, what, timeout_s=600, interval_s=3):
    """Teardown step that may hit a dependency still being released; retry within a window."""
    deadline = time.time() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code.endswith("NotFound") or code.endswith("NotFoundFault") or ".NotFound" in code:
                return
            if time.time() >= deadline:
                raise AssertionError(f"could not delete {what}: {code}") from exc
        time.sleep(interval_s)


def _create_subnet_group(ctx, rs):
    """A VPC, one subnet and a cluster subnet group this check owns; returns the group name."""
    ec2 = ctx.client("ec2")
    _, azs = _node_type_and_azs(rs)
    offered = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = [az for az in azs if az in offered] or sorted(offered)
    if not usable:
        raise AssertionError("no available AZ in this region for the cluster subnet")
    tags = [{"Key": "sim2real-behavioral", "Value": "true"}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id), f"vpc {vpc_id}"))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.91.0.0/24",
        AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_retrying(lambda: ec2.delete_subnet(SubnetId=subnet_id), f"subnet {subnet_id}")
    )
    group_name = ctx.unique_name("sim2real-behav-rs-subg-")
    rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="sim2real behavioral check",
        SubnetIds=[subnet_id],
        Tags=tags,
    )
    ctx.on_cleanup(
        lambda: _delete_retrying(
            lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=group_name),
            f"cluster subnet group {group_name}",
        )
    )
    return group_name


def _delete_snapshot_quiet(rs, snapshot_id):
    """Teardown: delete the manual snapshot unless the check already removed it."""
    try:
        rs.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if _code_of(exc) not in _NOT_FOUND_SNAPSHOT:
            raise


_NOT_FOUND_SNAPSHOT = ("ClusterSnapshotNotFound", "ClusterSnapshotNotFoundFault")


def _snapshot_status(rs, snapshot_id, cluster_id=None):
    kwargs = {"SnapshotIdentifier": snapshot_id} if snapshot_id else {"ClusterIdentifier": cluster_id}
    try:
        resp = _retrying(lambda: rs.describe_cluster_snapshots(**kwargs))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_SNAPSHOT + _NOT_FOUND_CLUSTER:
            return None
        raise
    snaps = resp.get("Snapshots", [])
    return snaps[0]["Status"] if snaps else None


def _wait_for_snapshot_status(
    rs, snapshot_id, target_statuses, cluster_id=None, timeout_s=420, interval_s=2, ctx=None
):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _snapshot_status(rs, snapshot_id, cluster_id=cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"snapshot {snapshot_id} status in {sorted(str(t) for t in targets)}",
        ctx=ctx,
    )

CHECK = "snapshot-create-delete-lifecycle"
GROUP = 'snapshot-lifecycle'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateClusterSnapshot: creating -> available, retention is mutable, delete removes it."""
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-snap-")
    subnet_group_name = _create_subnet_group(ctx, rs)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id, subnet_group_name))
    _wait_for_cluster_available(rs, cluster_id, timeout_s=480, ctx=ctx)

    snapshot_id = ctx.unique_name("sim2real-behav-rs-snap-s-")
    ctx.on_cleanup(lambda: _delete_snapshot_quiet(rs, snapshot_id))
    snap = rs.create_cluster_snapshot(
        SnapshotIdentifier=snapshot_id,
        ClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )["Snapshot"]
    assert snap["SnapshotIdentifier"] == snapshot_id
    assert snap["ClusterIdentifier"] == cluster_id
    assert snap["SnapshotType"] == "manual", f"expected a manual snapshot, got {snap['SnapshotType']}"
    assert snap["Status"] == "creating", f"expected creating, got {snap['Status']}"
    assert snap["NodeType"] == _node_type(rs)

    status = _wait_for_snapshot_status(rs, snapshot_id, "available", cluster_id=cluster_id, timeout_s=300, ctx=ctx)
    assert status == "available", f"snapshot never became available, status={status}"

    described = rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]
    assert described["MasterUsername"] == ADMIN_USERNAME
    assert described["ManualSnapshotRetentionPeriod"] == -1, (
        f"manual snapshots default to indefinite retention (-1), got {described['ManualSnapshotRetentionPeriod']}"
    )

    modified = rs.modify_cluster_snapshot(
        SnapshotIdentifier=snapshot_id, ManualSnapshotRetentionPeriod=5
    )["Snapshot"]
    assert modified["ManualSnapshotRetentionPeriod"] == 5

    batch = rs.batch_modify_cluster_snapshots(
        SnapshotIdentifierList=[snapshot_id], ManualSnapshotRetentionPeriod=7
    )
    assert batch["Resources"] == [snapshot_id], batch
    assert not batch.get("Errors"), batch
    after = rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]
    assert after["ManualSnapshotRetentionPeriod"] == 7

    rs.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id)
    gone = _wait_for_snapshot_status(rs, snapshot_id, {None, "deleted"}, timeout_s=240, ctx=ctx)
    assert gone in (None, "deleted"), f"snapshot still present after delete, status={gone}"

    # The retention modify that succeeded twice above must now fail on the dead id,
    # with the same not-found code the target reports for a snapshot that never existed.
    dead_code, dead_message = _expect_error(
        lambda: rs.modify_cluster_snapshot(
            SnapshotIdentifier=snapshot_id, ManualSnapshotRetentionPeriod=3
        )
    )
    assert dead_code == "ClusterSnapshotNotFound", (
        f"expected ClusterSnapshotNotFound modifying a deleted snapshot, got {dead_code}"
    )
    expected_message = f"ClusterSnapshot not found: {snapshot_id}"
    assert dead_message == expected_message, (
        f"expected message {expected_message!r}, got {dead_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
