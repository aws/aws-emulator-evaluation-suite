"""copy-cluster-snapshot-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-cluster-snapshot-contract"
GROUP = 'snapshots'
SERVICES = ['rds']

ERR_DB_CLUSTER_SNAPSHOT_NOT_FOUND = "DBClusterSnapshotNotFoundFault"


def _copy(rds, source, target):
    try:
        rds.copy_db_cluster_snapshot(
            SourceDBClusterSnapshotIdentifier=source,
            TargetDBClusterSnapshotIdentifier=target,
        )
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"copy_db_cluster_snapshot unexpectedly succeeded for source={source!r} target={target!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CopyDBClusterSnapshot from an unknown source snapshot is rejected with
    DBClusterSnapshotNotFoundFault, a target identifier breaking the naming rule is rejected for a
    different reason, and the rejected copy's target never exists."""
    rds = ctx.client("rds")
    bogus_src = ctx.unique_name("sim2real-behav-clusnap-missing-")
    target_id = ctx.unique_name("sim2real-behav-clusnap-tgt-")

    bad_target = "1" + target_id  # violates "first character must be a letter"
    control_code, _control_message = _copy(rds, bogus_src, bad_target)
    assert control_code != ERR_DB_CLUSTER_SNAPSHOT_NOT_FOUND, (
        f"malformed target {bad_target!r} returned the same code as a missing "
        f"source ({control_code!r}) — the rejection is not specific to the source"
    )

    code, message = _copy(rds, bogus_src, target_id)
    assert code == ERR_DB_CLUSTER_SNAPSHOT_NOT_FOUND, f"unexpected error code: {code!r}"
    assert message == f"Requested snapshot {bogus_src} not found in source region {ctx.region}", message

    try:
        rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=target_id)
        raise AssertionError(f"target {target_id!r} unexpectedly exists after a rejected copy")
    except ClientError as exc:
        found_code = exc.response.get("Error", {}).get("Code")
        assert found_code == ERR_DB_CLUSTER_SNAPSHOT_NOT_FOUND, (
            f"expected the never-created target to read back {ERR_DB_CLUSTER_SNAPSHOT_NOT_FOUND!r}, "
            f"got {found_code!r}"
        )
        found_message = exc.response.get("Error", {}).get("Message")
        assert found_message == f"DBClusterSnapshot not found: {target_id}", found_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
