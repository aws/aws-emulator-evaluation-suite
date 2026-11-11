"""instance-event-window-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceEventWindowIDNotFound":
            raise


CHECK = "instance-event-window-lifecycle"
GROUP = 'instance-lifecycle'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstanceEventWindow rejects conflicting schedules; a created window transitions
    to active and, once deleted, is independently unreadable and rejects a further delete."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-iew-")

    both, both_message = _error(
        lambda: ec2.create_instance_event_window(
            Name=ctx.unique_name("sim2real-iew-bad-"),
            TimeRanges=[
                {
                    "StartWeekDay": "monday",
                    "StartHour": 2,
                    "EndWeekDay": "monday",
                    "EndHour": 6,
                }
            ],
            CronExpression="* 21-23 * * 2,3",
        )
    )
    assert both == "InvalidParameterValue", (
        f"expected InvalidParameterValue for TimeRanges+CronExpression, got {both}"
    )
    expected = "The parameter cronExpression cannot be used with the timeRangesSet."
    assert both_message == expected, f"expected message {expected!r}, got {both_message!r}"

    resp = ec2.create_instance_event_window(
        Name=name,
        TimeRanges=[
            {
                "StartWeekDay": "monday",
                "StartHour": 2,
                "EndWeekDay": "monday",
                "EndHour": 6,
            }
        ],
        TagSpecifications=[{"ResourceType": "instance-event-window", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    window = resp["InstanceEventWindow"]
    window_id = window["InstanceEventWindowId"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ec2.delete_instance_event_window(
                InstanceEventWindowId=window_id, ForceDelete=True
            )
        )
    )
    assert window["State"] in ("creating", "active"), f"unexpected state {window['State']}"

    # Grade the terminal state on every target: poll until the window is active.
    deadline = time.monotonic() + 120
    state = window["State"]
    while True:
        if state == "active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the event window to become active within 120s, got {state!r}")
        time.sleep(3)
        state = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])[
            "InstanceEventWindows"
        ][0]["State"]

    out = ec2.delete_instance_event_window(InstanceEventWindowId=window_id)
    assert out["InstanceEventWindowState"]["State"] in ("deleting", "deleted"), f"got {out}"

    # Independent read at the destination: the deleted window must be genuinely gone, not
    # merely reported as such by the delete call's own response (instance event windows are
    # hard-deleted, so describing the dead id is itself rejected).
    describe_code, describe_message = _error(
        lambda: ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])
    )
    assert describe_code == "InvalidInstanceEventWindowIDNotFound", (
        f"expected a deleted event window to be independently unreadable, got {describe_code!r}"
    )
    expected = f"Invalid Instance Event Window IDs [{window_id}]."
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    # A further mutation against the dead id is rejected too, not silently accepted.
    redelete_code, redelete_message = _error(
        lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id)
    )
    assert redelete_code == "InvalidInstanceEventWindowIDNotFound", (
        f"expected InvalidInstanceEventWindowIDNotFound deleting an already-deleted window, got {redelete_code!r}"
    )
    expected = f"Invalid Instance Event Window ID {window_id}."
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
