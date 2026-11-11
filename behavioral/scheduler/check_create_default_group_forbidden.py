"""create-default-group-forbidden."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-default-group-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: creating a group literally named 'default' must be rejected, not treated as a fresh create."""
    sch = ctx.client("scheduler")

    code, message = _error_code(lambda: sch.create_schedule_group(Name="default"))
    assert code == "ValidationException", f"expected reserved-name rejection, got {code}"
    expected_message = "This operation cannot be performed on schedule group default."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the pre-existing default group is unaffected by the rejected call.
    default_group = sch.get_schedule_group(Name="default")
    assert default_group["State"] == "ACTIVE", (
        f"default group left in state {default_group.get('State')}"
    )

    # Positive control: an ordinary create (not named 'default') succeeds on this account,
    # so the rejection above is about the reserved name, not a broken CreateScheduleGroup call.
    group_name = ctx.unique_name("sim2real-behav-sched-grp-")
    sch.create_schedule_group(Name=group_name, Tags=[{"Key": "sim2real-behav", "Value": CHECK}])
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=group_name))
    control_state = sch.get_schedule_group(Name=group_name)["State"]
    assert control_state == "ACTIVE", f"expected ordinary group ACTIVE, got {control_state}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
