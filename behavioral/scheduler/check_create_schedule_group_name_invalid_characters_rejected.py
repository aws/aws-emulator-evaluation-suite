"""create-schedule-group-name-invalid-characters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-group-name-invalid-characters-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScheduleGroup with a name violating the ^[0-9a-zA-Z-_.]+$ pattern is
    rejected with ValidationException, and never comes into existence."""
    scheduler = ctx.client("scheduler")

    good_name = ctx.unique_name("sim2real-sched-grp-ok-")
    scheduler.create_schedule_group(Name=good_name)
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=good_name))

    bad_prefix = ctx.unique_name("sim2real-sched-grp-bad-")
    bad_name = bad_prefix + "@invalid#name"
    pattern_message = (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [0-9a-zA-Z-_.]+"
    )
    code, message = _error(lambda: scheduler.create_schedule_group(Name=bad_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == pattern_message, f"expected message {pattern_message!r}, got {message!r}"

    # GetScheduleGroup applies the same name-pattern validation to its Name parameter, so a
    # lookup by this invalid name is itself rejected with ValidationException rather than
    # ResourceNotFoundException -- the name never becomes a valid identifier to look up in the
    # first place. That means Get cannot serve as the absence proof; ListScheduleGroups does,
    # below.
    get_code, get_message = _error(lambda: scheduler.get_schedule_group(Name=bad_name))
    assert get_code == "ValidationException", f"expected ValidationException, got {get_code!r}"
    assert get_message == pattern_message, f"expected message {pattern_message!r}, got {get_message!r}"

    # effect absent, via an independent read: bad_prefix (the valid portion of bad_name) is
    # unique to this run, so any group listed under it would have to be the one the rejected
    # create tried to make.
    listed = scheduler.list_schedule_groups(NamePrefix=bad_prefix).get("ScheduleGroups", [])
    assert listed == [], f"rejected create left a resource behind: {listed}"

    # a syntactically valid but nonexistent name correctly yields ResourceNotFoundException
    never_created_name = ctx.unique_name("sim2real-sched-grp-missing-")
    missing_code, missing_message = _error(lambda: scheduler.get_schedule_group(Name=never_created_name))
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {missing_code!r}"
    )
    expected_missing = f"Schedule group {never_created_name} does not exist."
    assert missing_message == expected_missing, (
        f"expected message {expected_missing!r}, got {missing_message!r}"
    )

    # positive control still stands
    group = scheduler.get_schedule_group(Name=good_name)
    assert group["Name"] == good_name, f"expected {good_name!r}, got {group['Name']!r}"
    assert group["State"] == "ACTIVE", f"expected ACTIVE, got {group['State']!r}"


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
