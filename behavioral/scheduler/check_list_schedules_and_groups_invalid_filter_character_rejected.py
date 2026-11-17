"""list-schedules-and-groups-invalid-filter-character-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-schedules-and-groups-invalid-filter-character-rejected"
GROUP = "overly-permissive"
SERVICES = ["scheduler"]

_INVALID_VALUE = "not valid!"
_PATTERN_TAIL = "failed to satisfy constraint: Member must satisfy regular expression pattern: [0-9a-zA-Z-_.]+"
_GROUPS_NAME_PREFIX_INVALID = (
    "ValidationException",
    f"1 validation error detected: Value '{_INVALID_VALUE}' at 'namePrefix' {_PATTERN_TAIL}",
)
_SCHEDULES_NAME_PREFIX_INVALID = (
    "ValidationException",
    f"1 validation error detected: Value '{_INVALID_VALUE}' at 'namePrefix' {_PATTERN_TAIL}",
)
_SCHEDULES_GROUP_NAME_INVALID = (
    "ValidationException",
    f"1 validation error detected: Value '{_INVALID_VALUE}' at 'groupName' {_PATTERN_TAIL}",
)


def _expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        actual_code = exc.response.get("Error", {}).get("Code")
        actual_message = exc.response.get("Error", {}).get("Message")
        assert actual_code == code, f"expected {code!r}, got {actual_code!r} (message={actual_message!r})"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected the call to be refused with {code!r}, but it succeeded: {result!r}")


def _track_group(ctx, name):
    sch = ctx.client("scheduler")

    def _del():
        try:
            sch.delete_schedule_group(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_del)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListScheduleGroups and ListSchedules reject a NamePrefix outside [0-9A-Za-z-_.], and
    ListSchedules rejects a GroupName outside that same set, with the exact validation message;
    a well-formed filter of the same shape still succeeds."""
    sch = ctx.client("scheduler")
    group = ctx.unique_name("sim2real-behav-sched-grp-")
    sch.create_schedule_group(Name=group, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    _track_group(ctx, group)

    _expect_error(
        lambda: sch.list_schedule_groups(NamePrefix=_INVALID_VALUE), *_GROUPS_NAME_PREFIX_INVALID
    )
    groups_control = sch.list_schedule_groups(NamePrefix=group)["ScheduleGroups"]
    assert {g["Name"] for g in groups_control} == {group}, (
        f"well-formed NamePrefix={group!r} returned {[g['Name'] for g in groups_control]}, "
        f"expected exactly [{group!r}]"
    )

    _expect_error(
        lambda: sch.list_schedules(NamePrefix=_INVALID_VALUE), *_SCHEDULES_NAME_PREFIX_INVALID
    )
    _expect_error(
        lambda: sch.list_schedules(GroupName=_INVALID_VALUE), *_SCHEDULES_GROUP_NAME_INVALID
    )
    schedules_control = sch.list_schedules(GroupName=group)["Schedules"]
    assert schedules_control == [], (
        f"well-formed GroupName={group!r} on a group with no schedules returned "
        f"{schedules_control!r}, expected an empty list"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
