"""op-contract-modify-instance-event-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-instance-event-window"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceEventWindow updates the schedule of an event window and rejects a cron+time-range combo."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-behav-eventwin-")
    window = ec2.create_instance_event_window(
        Name=name,
        TimeRanges=[{"StartWeekDay": "monday", "StartHour": 0, "EndWeekDay": "monday", "EndHour": 4}],
        TagSpecifications=[
            {"ResourceType": "instance-event-window", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["InstanceEventWindow"]
    window_id = window["InstanceEventWindowId"]
    ctx.on_cleanup(lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id))

    new_name = ctx.unique_name("sim2real-behav-eventwin-renamed-")
    resp = ec2.modify_instance_event_window(
        InstanceEventWindowId=window_id,
        Name=new_name,
        TimeRanges=[{"StartWeekDay": "tuesday", "StartHour": 0, "EndWeekDay": "tuesday", "EndHour": 4}],
    )
    updated = resp["InstanceEventWindow"]
    assert updated["Name"] == new_name, updated
    assert updated["TimeRanges"][0]["StartWeekDay"] == "tuesday", updated

    described = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])[
        "InstanceEventWindows"
    ][0]
    assert described["Name"] == new_name, described

    # A cron expression and explicit time ranges are mutually-exclusive scheduling
    # mechanisms for the same window.
    code, msg = _error(
        lambda: ec2.modify_instance_event_window(
            InstanceEventWindowId=window_id,
            CronExpression="* 0-4 * * 1",
            TimeRanges=[{"StartWeekDay": "monday", "StartHour": 0, "EndWeekDay": "monday", "EndHour": 4}],
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {code}"
    )
    expected = "The parameter cronExpression cannot be used with the timeRangesSet."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # The rejected call must not have mutated the window: an independent read still
    # shows the Tuesday time range from the earlier, successful modify, and no cron
    # expression was installed alongside it.
    after_reject = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])[
        "InstanceEventWindows"
    ][0]
    assert after_reject.get("CronExpression") in (None, ""), (
        f"rejected modify must not install a cron expression, got {after_reject}"
    )
    assert after_reject["TimeRanges"][0]["StartWeekDay"] == "tuesday", after_reject


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
