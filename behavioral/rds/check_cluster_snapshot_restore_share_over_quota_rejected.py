"""cluster-snapshot-restore-share-over-quota-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-snapshot-restore-share-over-quota-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sharing a cluster snapshot with 21 accounts in one call is rejected whole with
    SharedSnapshotQuotaExceeded and grants none of them; a within-quota share naming the owner's
    own account is accepted yet never appears, and revoking an account never granted is a no-op."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-snapquota-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    _wait_cluster_status(rds, cluster_id, "available", timeout_s=1200)

    snapshot_id = ctx.unique_name("sim2real-snapquota-snap-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snapshot_id, DBClusterIdentifier=cluster_id
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snapshot_id))
    _wait_snapshot_status(rds, snapshot_id, "available", timeout_s=1200)

    # One call naming 21 accounts, one over the quota of 20; the call fails before any grant.
    over_quota = [_placeholder_account(i) for i in range(21)]
    code, message = _error_detail(
        lambda: rds.modify_db_cluster_snapshot_attribute(
            DBClusterSnapshotIdentifier=snapshot_id,
            AttributeName="restore",
            ValuesToAdd=over_quota,
        )
    )
    assert code == "SharedSnapshotQuotaExceeded", f"unexpected error code {code!r}: {message!r}"
    expected = "A snapshot cannot be shared with more than 20 customers."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    after_reject = _restore_values(rds, snapshot_id)
    assert after_reject == [], (
        f"expected no account granted by the rejected over-quota share, got {after_reject!r}"
    )

    # Within quota (one account, naming only this run's own account, never a stranger's), the
    # call is accepted rather than rejected whole — distinguishing this from the over-quota
    # rejection above — but the owner can never appear in their own restore list: the add's own
    # echo and two further independent reads all stay empty.
    own_account = ctx.account
    add_result = rds.modify_db_cluster_snapshot_attribute(
        DBClusterSnapshotIdentifier=snapshot_id,
        AttributeName="restore",
        ValuesToAdd=[own_account],
    )["DBClusterSnapshotAttributesResult"]
    echoed_self_add = [
        a.get("AttributeValues", [])
        for a in add_result.get("DBClusterSnapshotAttributes", [])
        if a["AttributeName"] == "restore"
    ]
    assert echoed_self_add == [[]], (
        f"expected the owner-account share to echo an empty restore attribute, got {echoed_self_add!r}"
    )
    self_add_reads = [_restore_values(rds, snapshot_id) for _ in range(3)]
    assert self_add_reads == [[]] * 3, (
        f"expected the restore attribute to stay empty across repeated reads after sharing "
        f"with the owner account {own_account!r}, got {self_add_reads!r}"
    )

    # Positive control with no grant: the same operation, removing an account never added.
    result = rds.modify_db_cluster_snapshot_attribute(
        DBClusterSnapshotIdentifier=snapshot_id,
        AttributeName="restore",
        ValuesToRemove=[over_quota[0]],
    )["DBClusterSnapshotAttributesResult"]
    assert result["DBClusterSnapshotIdentifier"] == snapshot_id, (
        f"the attribute result names snapshot {result.get('DBClusterSnapshotIdentifier')!r}, "
        f"expected {snapshot_id!r}"
    )
    echoed = [
        a.get("AttributeValues", [])
        for a in result.get("DBClusterSnapshotAttributes", [])
        if a["AttributeName"] == "restore"
    ]
    assert echoed == [[]], f"expected an empty restore attribute in the response, got {echoed!r}"

    after_revoke = _restore_values(rds, snapshot_id)
    assert after_revoke == [], (
        f"expected the restore attribute to stay empty after the revoke, got {after_revoke!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _placeholder_account(n: int) -> str:
    return f"{100000000000 + n:012d}"


def _error_detail(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_cluster_status(rds, cluster_id, target_status, timeout_s, poll_s=15) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]
        if last == target_status:
            return
        time.sleep(poll_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_status!r}, last {last!r}")


def _wait_snapshot_status(rds, snapshot_id, target_status, timeout_s, poll_s=15) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)[
            "DBClusterSnapshots"
        ][0]["Status"]
        if last == target_status:
            return
        time.sleep(poll_s)
    raise AssertionError(f"snapshot {snapshot_id} never reached {target_status!r}, last {last!r}")


def _restore_values(rds, snapshot_id) -> list[str]:
    result = rds.describe_db_cluster_snapshot_attributes(
        DBClusterSnapshotIdentifier=snapshot_id
    )["DBClusterSnapshotAttributesResult"]
    for attr in result.get("DBClusterSnapshotAttributes", []):
        if attr["AttributeName"] == "restore":
            return list(attr.get("AttributeValues", []))
    return []


def _delete_snapshot(rds, snapshot_id) -> None:
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterSnapshotNotFoundFault":
            raise


def _delete_cluster(rds, cluster_id) -> None:
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
