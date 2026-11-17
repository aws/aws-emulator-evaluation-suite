"""snapshot-schedule-duplicate-create-and-modify-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-schedule-duplicate-create-and-modify-unknown-rejected"
GROUP = "scheduling"
SERVICES = ["redshift"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_unless_gone(delete, gone_code):
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A duplicate CreateSnapshotSchedule identifier is rejected and leaves the original
    definition unchanged; ModifySnapshotSchedule on an unknown identifier is rejected too."""
    rs = ctx.client("redshift")
    schedule_id = ctx.unique_name("sim2real-behav-rs-sspdup-")
    ctx.on_cleanup(
        lambda: _delete_unless_gone(
            lambda: rs.delete_snapshot_schedule(ScheduleIdentifier=schedule_id),
            "SnapshotScheduleNotFound",
        )
    )

    created = rs.create_snapshot_schedule(
        ScheduleIdentifier=schedule_id,
        ScheduleDescription="behavioral fidelity positive control",
        ScheduleDefinitions=["rate(12 hours)"],
    )
    assert created["ScheduleDefinitions"] == ["rate(12 hours)"], created

    code, message = _error(
        lambda: rs.create_snapshot_schedule(
            ScheduleIdentifier=schedule_id,
            ScheduleDescription="behavioral fidelity duplicate attempt",
            ScheduleDefinitions=["rate(24 hours)"],
        )
    )
    assert code == "SnapshotScheduleAlreadyExists", f"expected SnapshotScheduleAlreadyExists, got {code}: {message!r}"
    expected_dup = f"Snapshot schedule {schedule_id} already exists."
    assert message == expected_dup, f"expected message {expected_dup!r}, got {message!r}"

    unchanged = rs.describe_snapshot_schedules(ScheduleIdentifier=schedule_id)["SnapshotSchedules"]
    assert len(unchanged) == 1, unchanged
    assert unchanged[0]["ScheduleDefinitions"] == ["rate(12 hours)"], (
        f"a rejected duplicate create must not have overwritten the original definition: {unchanged[0]!r}"
    )

    missing_id = ctx.unique_name("sim2real-behav-rs-sspmissing-")
    code, message = _error(
        lambda: rs.modify_snapshot_schedule(
            ScheduleIdentifier=missing_id, ScheduleDefinitions=["rate(12 hours)"]
        )
    )
    assert code == "SnapshotScheduleNotFound", f"expected SnapshotScheduleNotFound, got {code}: {message!r}"
    expected_missing = f"No snapshot schedule found for schedule identifier {missing_id}"
    assert message == expected_missing, f"expected message {expected_missing!r}, got {message!r}"

    never_created = rs.describe_snapshot_schedules(ScheduleIdentifier=missing_id)["SnapshotSchedules"]
    assert never_created == [], f"a rejected modify must not have created the schedule: {never_created}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
