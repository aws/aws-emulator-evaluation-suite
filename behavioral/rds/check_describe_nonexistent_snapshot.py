"""describe-nonexistent-snapshot."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-snapshot"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_SNAPSHOT_NOT_FOUND = "DBSnapshotNotFound"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBSnapshots with nonexistent ID raises DBSnapshotNotFound; an unfiltered call on
    the same API must still succeed, so the rejection is about this identifier and not evidence
    that the account/credentials reject every DescribeDBSnapshots call."""
    rds = ctx.client("rds")

    control = rds.describe_db_snapshots(MaxRecords=20)
    assert "DBSnapshots" in control, (
        f"positive control failed: unfiltered describe_db_snapshots returned {control!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-snap-")
    try:
        rds.describe_db_snapshots(DBSnapshotIdentifier=ghost)
        code = message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_SNAPSHOT_NOT_FOUND, f"expected {ERR_DB_SNAPSHOT_NOT_FOUND}, got {code!r}"
    assert message == f"DBSnapshot not found: {ghost}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
