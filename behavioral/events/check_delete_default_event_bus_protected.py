"""delete-default-event-bus-protected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-default-event-bus-protected"
GROUP = 'event-bus'
SERVICES = ['events']

def _error_code(fn):
    """(code, message) for a call that fails; a sentinel that cannot be mistaken for a real
    code, plus the response, if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "<call unexpectedly SUCCEEDED>", resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventBus works on a real bus but is rejected against "default"."""
    ev = ctx.client("events")

    # Positive control: DeleteEventBus actually deletes buses in this account, so the rejection
    # below is specific to "default" and not evidence of a target where delete never works.
    control_name = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=control_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda n=control_name: ev.delete_event_bus(Name=n))
    ev.delete_event_bus(Name=control_name)
    control_code, control_detail = _error_code(lambda: ev.describe_event_bus(Name=control_name))
    assert control_code == "ResourceNotFoundException", (
        f"positive control: expected the custom bus gone after delete, got {control_code!r} "
        f"({control_detail!r})"
    )

    code, message = _error_code(lambda: ev.delete_event_bus(Name="default"))
    assert code == "ValidationException", (
        f"expected ValidationException deleting the default event bus, got {code!r} ({message!r})"
    )
    assert message == "Cannot delete event bus default.", (
        f"expected the specific default-bus refusal message, got {message!r}"
    )

    desc = ev.describe_event_bus(Name="default")
    assert desc["Name"] == "default", (
        f"default event bus must survive a delete attempt, got {desc.get('Name')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
