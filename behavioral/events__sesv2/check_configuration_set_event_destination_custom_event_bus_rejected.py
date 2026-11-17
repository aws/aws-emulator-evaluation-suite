"""configuration-set-event-destination-custom-event-bus-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-event-destination-custom-event-bus-rejected"
GROUP = "configuration-set-event-destinations"
SERVICES = ["events", "sesv2"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _dest(ses, cs_name: str, ed_name: str):
    for d in ses.get_configuration_set_event_destinations(ConfigurationSetName=cs_name)["EventDestinations"]:
        if d["Name"] == ed_name:
            return d
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetEventDestination and UpdateConfigurationSetEventDestination refuse an
    EventBridgeDestination naming a non-default event bus, leaving stored destinations on the
    default bus.
    """
    events = ctx.client("events")
    ses = ctx.client("sesv2")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(_teardown(lambda: events.delete_event_bus(Name=bus_name), "ResourceNotFoundException"))
    custom_bus_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/{bus_name}"
    default_bus_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/default"

    cs_name = ctx.unique_name("sim2real-behav-v2cs-")
    ses.create_configuration_set(ConfigurationSetName=cs_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: ses.delete_configuration_set(ConfigurationSetName=cs_name), "NotFoundException"))

    control_name = "ed-eb-default"
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cs_name,
        EventDestinationName=control_name,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "EventBridgeDestination": {"EventBusArn": default_bus_arn},
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: ses.delete_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName=control_name
        ),
        "NotFoundException",
    ))
    control = _dest(ses, cs_name, control_name)
    assert control is not None, "positive control: destination on the default bus not visible via a read"
    assert control["EventBridgeDestination"]["EventBusArn"] == default_bus_arn, (
        f"expected the control destination to name the default bus, got {control['EventBridgeDestination']!r}"
    )

    reject_name = "ed-eb-custom"
    code, message = _error(lambda: ses.create_configuration_set_event_destination(
        ConfigurationSetName=cs_name,
        EventDestinationName=reject_name,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "EventBridgeDestination": {"EventBusArn": custom_bus_arn},
        },
    ))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    expected_create_msg = "Invalid Event Bridge destination, must be default bus."
    assert message == expected_create_msg, f"expected message {expected_create_msg!r}, got {message!r}"
    assert _dest(ses, cs_name, reject_name) is None, (
        "rejected create must not add a destination for the non-default bus"
    )

    code, message = _error(lambda: ses.update_configuration_set_event_destination(
        ConfigurationSetName=cs_name,
        EventDestinationName=control_name,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "EventBridgeDestination": {"EventBusArn": custom_bus_arn},
        },
    ))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    expected_update_msg = "Invalid Event Bridge destination, must be default bus."
    assert message == expected_update_msg, f"expected message {expected_update_msg!r}, got {message!r}"
    unchanged = _dest(ses, cs_name, control_name)
    assert unchanged is not None, "the existing destination disappeared after a rejected update"
    assert unchanged["EventBridgeDestination"]["EventBusArn"] == default_bus_arn, (
        f"the rejected update must leave the destination on the default bus, got {unchanged['EventBridgeDestination']!r}"
    )
    assert set(unchanged["MatchingEventTypes"]) == {"SEND"}, (
        f"the rejected update must leave the destination's other fields untouched, got {unchanged['MatchingEventTypes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
