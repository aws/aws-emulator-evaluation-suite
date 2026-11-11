"""op-contract-delete-instance-event-window."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-instance-event-window"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteInstanceEventWindow: a freshly created, unassociated event window deletes cleanly
    and moves to the 'deleting' state; deleting an unknown event window ID is rejected rather
    than silently accepted.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eventwin-")

    window = ec2.create_instance_event_window(
        Name=name,
        TimeRanges=[{"StartWeekDay": "sunday", "StartHour": 2, "EndWeekDay": "sunday", "EndHour": 6}],
        TagSpecifications=[{"ResourceType": "instance-event-window", "Tags": [{"Key": "Name", "Value": name}]}],
    )["InstanceEventWindow"]
    window_id = window["InstanceEventWindowId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id)))

    resp = ec2.delete_instance_event_window(InstanceEventWindowId=window_id)
    state = resp["InstanceEventWindowState"]
    assert state["InstanceEventWindowId"] == window_id, (
        f"expected the delete response to name {window_id!r}, got {state['InstanceEventWindowId']!r}"
    )
    assert state["State"] in ("deleting", "deleted"), state

    # Instance event windows are hard-deleted: describing the deleted window by ID is itself
    # rejected (rather than returning an empty/deleting-state list) — that rejection is the
    # confirmation that the delete took effect.
    describe_code, describe_message = _error(
        lambda: ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])
    )
    assert describe_code == "InvalidInstanceEventWindowIDNotFound", f"unexpected error code {describe_code!r}"
    assert describe_message == f"Invalid Instance Event Window IDs [{window_id}].", describe_message

    # A mutation on the dead id also fails — re-deleting the window this check itself just
    # deleted must be rejected the same way, not silently accepted as a no-op.
    redelete_code, redelete_message = _error(
        lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id)
    )
    assert redelete_code == "InvalidInstanceEventWindowIDNotFound", f"unexpected error code {redelete_code!r}"
    assert redelete_message == f"Invalid Instance Event Window ID {window_id}.", redelete_message

    # Error boundary: deleting an unknown event window ID (one that never existed) is rejected too.
    fake_id = _zeroed_id(window_id)
    code, message = _error(lambda: ec2.delete_instance_event_window(InstanceEventWindowId=fake_id))
    assert code == "InvalidInstanceEventWindowIDNotFound", f"unexpected error code {code!r}"
    assert message == f"Invalid Instance Event Window ID {fake_id}.", message


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceEventWindowIDNotFound":
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
