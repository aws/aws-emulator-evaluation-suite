"""op-contract-describe-instance-event-windows."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-instance-event-windows"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceEventWindows reflects a real, created event window's time ranges and
    rejects a well-formed but nonexistent event window ID."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-event-window-")

    created = ec2.create_instance_event_window(
        Name=name,
        TimeRanges=[{"StartWeekDay": "sunday", "StartHour": 0, "EndWeekDay": "sunday", "EndHour": 4}],
        TagSpecifications=[{"ResourceType": "instance-event-window", "Tags": [{"Key": "Name", "Value": name}]}],
    )["InstanceEventWindow"]
    window_id = created["InstanceEventWindowId"]
    ctx.on_cleanup(lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id))

    described = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])[
        "InstanceEventWindows"
    ]
    assert len(described) == 1, f"expected exactly one event window for {window_id!r}, got {described}"
    window = described[0]
    assert window["Name"] == name, f"expected Name {name!r}, got {window['Name']!r}"
    time_ranges = window["TimeRanges"]
    assert len(time_ranges) == 1, f"expected exactly one time range, got {time_ranges}"
    tr = time_ranges[0]
    assert (tr["StartWeekDay"], tr["StartHour"], tr["EndWeekDay"], tr["EndHour"]) == (
        "sunday",
        0,
        "sunday",
        4,
    ), f"unexpected time range: {tr}"
    assert window["State"] in ("creating", "active"), f"unexpected state {window['State']!r}"

    by_name_filter = ec2.describe_instance_event_windows(
        Filters=[{"Name": "event-window-name", "Values": [name]}]
    )["InstanceEventWindows"]
    assert any(w["InstanceEventWindowId"] == window_id for w in by_name_filter), (
        f"expected {window_id!r} in event-window-name filter results, got "
        f"{[w['InstanceEventWindowId'] for w in by_name_filter]}"
    )

    # Error boundary: a well-formed but nonexistent event window ID is rejected, not
    # returned empty.
    bogus_window_id = "iew-0000000000000000f"
    code, message = _error(
        lambda: ec2.describe_instance_event_windows(InstanceEventWindowIds=[bogus_window_id])
    )
    assert code == "InvalidInstanceEventWindowIDNotFound", (
        f"expected InvalidInstanceEventWindowIDNotFound, got {code}"
    )
    expected = f"Invalid Instance Event Window IDs [{bogus_window_id}]."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
