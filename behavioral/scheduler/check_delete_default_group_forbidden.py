"""delete-default-group-forbidden."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-default-group-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteScheduleGroup on the reserved 'default' group is rejected with ValidationException and
    the group stays ACTIVE, while an ordinary group created by the check deletes normally."""
    sch = ctx.client("scheduler")

    # Break exactly one thing: try to delete the immutable default group.
    code, message = _error(lambda: sch.delete_schedule_group(Name="default"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "This operation cannot be performed on schedule group default."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the default group is still there and still ACTIVE (independent read).
    got = sch.get_schedule_group(Name="default")
    assert got["State"] == "ACTIVE", f"default group left in state {got.get('State')}"

    # Positive control: an ordinary group created by this check can be deleted.
    group_name = ctx.unique_name("sim2real-behav-delgrp-")
    sch.create_schedule_group(Name=group_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_group_if_present(sch, group_name))
    created_state = sch.get_schedule_group(Name=group_name)["State"]
    assert created_state == "ACTIVE", f"expected freshly-created group ACTIVE, got {created_state}"

    sch.delete_schedule_group(Name=group_name)
    deadline = time.monotonic() + 60
    deleted = False
    while time.monotonic() < deadline:
        try:
            sch.get_schedule_group(Name=group_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            deleted = True
            break
        time.sleep(2)
    assert deleted, "an ordinary schedule group was never actually removed after DeleteScheduleGroup"


def _delete_group_if_present(scheduler, name):
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
