"""automated-backups-replication-nonexistent-source-instance-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-backups-replication-nonexistent-source-instance-rejected"
GROUP = "automated_backups"
SERVICES = ["rds"]

_ERR_START_NOT_FOUND = "DBInstanceNotFound"
_ERR_STOP_NOT_REPLICATING = "InvalidDBInstanceState"


def _rejection(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Start rejects a source ARN naming an instance that does not exist with DBInstanceNotFound;
    Stop rejects the identical ARN with InvalidDBInstanceState because it is not replicating.
    A plain describe on the same account still succeeds."""
    rds = ctx.client("rds")

    control = rds.describe_db_instances(MaxRecords=20)
    assert "DBInstances" in control, (
        f"positive control failed: unfiltered describe_db_instances returned {control!r}"
    )

    ghost_id = ctx.unique_name("sim2real-dbi-")
    ghost_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:db:{ghost_id}"

    err_start = _rejection(
        lambda: rds.start_db_instance_automated_backups_replication(
            SourceDBInstanceArn=ghost_arn
        )
    )
    assert err_start.get("Code") == _ERR_START_NOT_FOUND, (
        f"Start on a nonexistent source instance: expected {_ERR_START_NOT_FOUND}, got {err_start}"
    )
    expected_start_msg = (
        f"Requested DB Instance {ghost_id} not found in source region {ctx.region}"
    )
    assert err_start.get("Message") == expected_start_msg, err_start.get("Message")

    err_stop = _rejection(
        lambda: rds.stop_db_instance_automated_backups_replication(
            SourceDBInstanceArn=ghost_arn
        )
    )
    assert err_stop.get("Code") == _ERR_STOP_NOT_REPLICATING, (
        f"Stop on the same ARN: expected {_ERR_STOP_NOT_REPLICATING}, got {err_stop}"
    )
    expected_stop_msg = f"DB Instance {ghost_arn} is not replicating to the current region."
    assert err_stop.get("Message") == expected_stop_msg, err_stop.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
