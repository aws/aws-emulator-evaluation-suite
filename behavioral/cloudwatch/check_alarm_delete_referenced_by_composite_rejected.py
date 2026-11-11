"""alarm-delete-referenced-by-composite-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-delete-referenced-by-composite-rejected"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on either member of a two-composite reference cycle fails with ValidationError
    "Cannot delete <name> as there are composite alarm(s) depending on it." and both stay; after one
    rule is rewritten to FALSE, both deletes succeed."""
    cw = ctx.client("cloudwatch")
    alarm_a = ctx.unique_name("sim2real-behav-cyclea-")
    alarm_b = ctx.unique_name("sim2real-behav-cycleb-")
    alarm_tags = [{"Key": "sim2real:managed", "Value": "true"}]

    # PutCompositeAlarm validates that any alarm named in AlarmRule already exists, so the
    # cycle must be built in two steps: create B first with a non-referencing rule, then A
    # referencing B (B exists), then rewrite B to reference A (A now exists too) -- closing
    # the cycle only after both alarms are already present.
    cw.put_composite_alarm(AlarmName=alarm_b, AlarmRule="FALSE", Tags=alarm_tags)
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [alarm_b]))

    cw.put_composite_alarm(AlarmName=alarm_a, AlarmRule=f'ALARM("{alarm_b}")', Tags=alarm_tags)
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [alarm_a]))

    cw.put_composite_alarm(AlarmName=alarm_b, AlarmRule=f'ALARM("{alarm_a}")')

    # The blocking condition: neither alarm in the cycle can be deleted. CloudWatch reports the
    # ordinary dependency refusal ("... as there are composite alarm(s) depending on it"), not a
    # distinct "cycle" error.
    code_a, msg_a = _error_code_and_message(lambda: cw.delete_alarms(AlarmNames=[alarm_a]))
    assert code_a == "ValidationError", f"expected ValidationError deleting cycle member A, got {code_a}: {msg_a}"
    expected_a = f"Cannot delete {alarm_a} as there are composite alarm(s) depending on it."
    assert msg_a == expected_a, f"expected message {expected_a!r}, got {msg_a!r}"
    code_b, msg_b = _error_code_and_message(lambda: cw.delete_alarms(AlarmNames=[alarm_b]))
    assert code_b == "ValidationError", f"expected ValidationError deleting cycle member B, got {code_b}: {msg_b}"
    expected_b = f"Cannot delete {alarm_b} as there are composite alarm(s) depending on it."
    assert msg_b == expected_b, f"expected message {expected_b!r}, got {msg_b!r}"

    # effect absent: both alarms must still exist, untouched
    still_there = cw.describe_alarms(AlarmNames=[alarm_a, alarm_b], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    found_names = {a["AlarmName"] for a in still_there}
    assert found_names == {alarm_a, alarm_b}, f"expected both cycle members present, found {found_names}"

    # break the cycle: rewrite B's rule to FALSE (the documented fix), removing the dependency
    cw.put_composite_alarm(AlarmName=alarm_b, AlarmRule="FALSE")

    # positive control: now that the cycle is broken, deleting A (no longer depended upon
    # in a cycle) succeeds, and deleting B succeeds too
    cw.delete_alarms(AlarmNames=[alarm_a])
    cw.delete_alarms(AlarmNames=[alarm_b])
    gone = cw.describe_alarms(AlarmNames=[alarm_a, alarm_b], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    assert gone == [], f"expected both cycle members gone after breaking the cycle, found {gone}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_alarms_ignore(cw, names: list[str]) -> None:
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
