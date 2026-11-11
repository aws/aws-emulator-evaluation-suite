"""snapshot-share-and-copy."""

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


def _wait_until(probe, done, timeout_s=600, interval_s=15, what="condition"):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _wait_for_cluster_status(rs, cluster_id, target_statuses, timeout_s=600, interval_s=15):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in targets)}",
    )


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_for_cluster_status(rs, cluster_id, terminal, timeout_s=timeout_s)
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_for_cluster_gone(rs, cluster_id, timeout_s=420, interval_s=15):
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
            if _code_of(exc) != "InvalidClusterState" or time.time() >= deadline:
                raise
        time.sleep(2)


def _delete_cluster_and_wait(rs, cluster_id):
    """Teardown: delete the cluster and wait until it is gone, so its subnet group and VPC
    can be deleted after it."""
    _delete_cluster(rs, cluster_id)
    _wait_for_cluster_gone(rs, cluster_id, timeout_s=900, interval_s=20)


_IN_USE = ("InvalidClusterSubnetGroupStateFault", "DependencyViolation", "InvalidClusterState")


def _delete_retrying(fn, what, timeout_s=180, interval_s=2):
    """Teardown step that may hit a dependency still being released: retry only the in-use
    refusals within a window that keeps every teardown inside the cleanup budget."""
    deadline = time.time() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code.endswith("NotFound") or code.endswith("NotFoundFault") or ".NotFound" in code:
                return
            if code not in _IN_USE:
                raise
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


def _wait_for_snapshot_status(rs, snapshot_id, target_statuses, cluster_id=None, timeout_s=420, interval_s=15):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _snapshot_status(rs, snapshot_id, cluster_id=cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"snapshot {snapshot_id} status in {sorted(str(t) for t in targets)}",
    )

CHECK = "snapshot-share-and-copy"
GROUP = 'snapshot-lifecycle'
SERVICES = ['redshift']

OTHER_ACCOUNT = "111122223333"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeSnapshotAccess/RevokeSnapshotAccess toggle cross-account restore access;
    CopyClusterSnapshot REFUSES a manual snapshot (only automated snapshots are copyable); and
    BatchDeleteClusterSnapshots reports per-item errors instead of failing the whole call."""
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-share-")
    subnet_group_name = _create_subnet_group(ctx, rs)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id, subnet_group_name))
    _wait_for_cluster_available(rs, cluster_id, timeout_s=420)

    snapshot_id = ctx.unique_name("sim2real-behav-rs-share-s-")
    ctx.on_cleanup(lambda: _delete_snapshot_quiet(rs, snapshot_id))
    rs.create_cluster_snapshot(
        SnapshotIdentifier=snapshot_id,
        ClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    _wait_for_snapshot_status(rs, snapshot_id, "available", cluster_id=cluster_id, timeout_s=300)

    rs.authorize_snapshot_access(
        SnapshotIdentifier=snapshot_id, AccountWithRestoreAccess=OTHER_ACCOUNT
    )
    granted = rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]
    accounts = [a.get("AccountId") for a in granted.get("AccountsWithRestoreAccess", [])]
    assert OTHER_ACCOUNT in accounts, f"expected restore access for {OTHER_ACCOUNT}, got {accounts}"

    rs.revoke_snapshot_access(
        SnapshotIdentifier=snapshot_id, AccountWithRestoreAccess=OTHER_ACCOUNT
    )
    revoked = rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]
    accounts_after = [a.get("AccountId") for a in revoked.get("AccountsWithRestoreAccess", [])]
    assert OTHER_ACCOUNT not in accounts_after, f"restore access should be revoked, got {accounts_after}"

    # CopyClusterSnapshot is only valid for AUTOMATED snapshots; copying the manual snapshot
    # above must be rejected and must not materialise a target snapshot.
    target_id = ctx.unique_name("sim2real-behav-rs-copy-s-")
    copy_code, copy_message = _expect_error(lambda: rs.copy_cluster_snapshot(
        SourceSnapshotIdentifier=snapshot_id, TargetSnapshotIdentifier=target_id
    ))
    assert copy_code == "InvalidParameterValue", (
        f"copying a manual snapshot must be rejected, got {copy_code}"
    )
    expected_copy_message = "Only automated snapshots can be copied."
    assert copy_message == expected_copy_message, (
        f"expected message {expected_copy_message!r}, got {copy_message!r}"
    )
    assert _snapshot_status(rs, target_id) is None, "the rejected copy must not exist"

    missing_id = ctx.unique_name("sim2real-behav-rs-nosnap-")
    batch = rs.batch_delete_cluster_snapshots(
        Identifiers=[{"SnapshotIdentifier": snapshot_id}, {"SnapshotIdentifier": missing_id}]
    )
    assert batch["Resources"] == [snapshot_id], batch
    errors = batch.get("Errors", [])
    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["SnapshotIdentifier"] == missing_id, (
        f"expected the per-item error to name {missing_id!r}, got {errors[0]!r}"
    )
    assert set(errors[0]) >= {"SnapshotIdentifier", "FailureCode", "FailureReason"}, errors[0]
    assert errors[0]["FailureCode"] == "ClusterSnapshotNotFoundFault", (
        f"unexpected per-item failure code: {errors[0]}"
    )
    expected_reason = "Snapshot does not exist for the customer."
    assert errors[0]["FailureReason"] == expected_reason, (
        f"expected failure reason {expected_reason!r}, got {errors[0]['FailureReason']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
