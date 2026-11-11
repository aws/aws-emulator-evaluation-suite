"""event-destination-duplicate-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destination-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _dest_by_name(ses, cfg_name, dest_name):
    desc = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    )
    return [d for d in desc.get("EventDestinations", []) if d["Name"] == dest_name]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetEventDestination rejects a duplicate name with
    EventDestinationAlreadyExists, leaves the existing destination untouched,
    and accepts the name again after it is deleted."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-dupdest-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    dest_name = ctx.unique_name("sim2real-behav-dest-")
    destination = {
        "Name": dest_name,
        "Enabled": True,
        "MatchingEventTypes": ["send"],
        "CloudWatchDestination": {
            "DimensionConfigurations": [
                {
                    "DimensionName": "probe-dimension",
                    "DimensionValueSource": "messageTag",
                    "DefaultDimensionValue": "none",
                }
            ]
        },
    }
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cfg_name, EventDestination=destination
    )
    created = _dest_by_name(ses, cfg_name, dest_name)
    assert len(created) == 1, (
        f"expected exactly one destination named {dest_name!r} after create, got {len(created)}"
    )

    err, msg = _err(
        lambda: ses.create_configuration_set_event_destination(
            ConfigurationSetName=cfg_name, EventDestination=destination
        )
    )
    assert err == "EventDestinationAlreadyExists", (
        f"expected EventDestinationAlreadyExists for a duplicate destination name, got {err!r}: {msg!r}"
    )
    expected_msg = (
        f"An event destination with name <{dest_name}> already exists for configuration set "
        f"<{cfg_name}>."
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    after_reject = _dest_by_name(ses, cfg_name, dest_name)
    assert len(after_reject) == 1, (
        f"expected the rejected create to leave exactly one destination named {dest_name!r}, "
        f"got {len(after_reject)}"
    )
    assert list(after_reject[0]["MatchingEventTypes"]) == ["send"], (
        "rejected duplicate create must not alter the existing destination, expected "
        f"MatchingEventTypes ['send'], got {after_reject[0]['MatchingEventTypes']!r}"
    )

    ses.delete_configuration_set_event_destination(
        ConfigurationSetName=cfg_name, EventDestinationName=dest_name
    )
    after_delete = _dest_by_name(ses, cfg_name, dest_name)
    assert after_delete == [], (
        f"expected destination {dest_name!r} gone after delete, still present: {after_delete!r}"
    )

    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cfg_name, EventDestination=destination
    )
    restored = _dest_by_name(ses, cfg_name, dest_name)
    assert len(restored) == 1, (
        f"expected the identical create to succeed once the name was freed, got "
        f"{len(restored)} matches"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
