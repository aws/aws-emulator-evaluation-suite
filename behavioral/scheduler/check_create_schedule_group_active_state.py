"""create-schedule-group-active-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-group-active-state"
GROUP = 'state-machine'
SERVICES = ['scheduler']

def _track_group(ctx, name):
    sch = ctx.client("scheduler")

    def _delete():
        try:
            sch.delete_schedule_group(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _group_exists(ctx, name):
    sch = ctx.client("scheduler")
    try:
        sch.get_schedule_group(Name=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException while polling deletion of {name!r}, got {code!r}"
        )
        message = exc.response.get("Error", {}).get("Message")
        expected = f"Schedule group {name} does not exist."
        assert message == expected, f"expected {expected!r}, got {message!r}"
        return False
    return True

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScheduleGroup produces a group that is immediately in ACTIVE state; DeleteScheduleGroup
    removes it, and both an independent read and a further mutation on the dead group return the
    specific ResourceNotFoundException rather than any generic failure."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-grp-")
    resp = sch.create_schedule_group(
        Name=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    _track_group(ctx, name)
    assert resp["ScheduleGroupArn"].endswith(f"/{name}"), (
        f"expected ScheduleGroupArn ending in /{name}, got {resp['ScheduleGroupArn']!r}"
    )

    got = sch.get_schedule_group(Name=name)
    assert got["Name"] == name, f"expected Name={name!r}, got {got['Name']!r}"
    assert got["State"] == "ACTIVE", (
        f"expected State=ACTIVE immediately after CreateScheduleGroup, got {got['State']!r}"
    )

    sch.delete_schedule_group(Name=name)
    _poll_until(
        lambda: _group_exists(ctx, name),
        lambda exists: not exists,
        timeout_s=30,
        interval_s=1,
        description=f"deletion of schedule group {name!r}",
    )

    expected_message = f"Schedule group {name} does not exist."
    code, message = _error_code(lambda: sch.get_schedule_group(Name=name))
    assert code == "ResourceNotFoundException", (
        f"expected GetScheduleGroup on a deleted group to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code, message = _error_code(lambda: sch.delete_schedule_group(Name=name))
    assert code == "ResourceNotFoundException", (
        "expected a second DeleteScheduleGroup on an already-deleted group to raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
