"""event-destination-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "event-destination-lifecycle"
GROUP = 'configuration-set'
SERVICES = ['ses']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Update/Delete of a CloudWatch event destination on a configuration set."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-evt-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    dest_name = ctx.unique_name("sim2real-behav-dest-")
    ses.create_configuration_set_event_destination(
        ConfigurationSetName=cfg_name,
        EventDestination={
            "Name": dest_name,
            "Enabled": True,
            "MatchingEventTypes": ["send", "bounce"],
            "CloudWatchDestination": {
                "DimensionConfigurations": [
                    {
                        "DimensionName": "probe-dimension",
                        "DimensionValueSource": "messageTag",
                        "DefaultDimensionValue": "none",
                    }
                ]
            },
        },
    )

    desc = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    )
    dests = {d["Name"]: d for d in desc.get("EventDestinations", [])}
    assert dest_name in dests, "event destination missing after create"
    assert dests[dest_name]["Enabled"] is True, (
        f"expected Enabled True after create, got {dests[dest_name]['Enabled']!r}"
    )
    assert set(dests[dest_name]["MatchingEventTypes"]) == {"send", "bounce"}, (
        f"expected {{'send', 'bounce'}} after create, got {set(dests[dest_name]['MatchingEventTypes'])!r}"
    )

    ses.update_configuration_set_event_destination(
        ConfigurationSetName=cfg_name,
        EventDestination={
            "Name": dest_name,
            "Enabled": False,
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
        },
    )
    desc2 = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    )
    dests2 = {d["Name"]: d for d in desc2.get("EventDestinations", [])}
    assert dests2[dest_name]["Enabled"] is False, "Enabled flag not updated"
    assert list(dests2[dest_name]["MatchingEventTypes"]) == ["send"], "MatchingEventTypes not replaced"

    ses.delete_configuration_set_event_destination(
        ConfigurationSetName=cfg_name, EventDestinationName=dest_name
    )
    desc3 = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    )
    names3 = [d["Name"] for d in desc3.get("EventDestinations", [])]
    assert dest_name not in names3, "event destination still present after delete"

    err = msg = None
    try:
        ses.update_configuration_set_event_destination(
            ConfigurationSetName=cfg_name,
            EventDestination={
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
            },
        )
    except ClientError as exc:
        err = exc.response.get("Error", {}).get("Code")
        msg = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("expected updating a deleted event destination to fail, but it SUCCEEDED")
    assert err == "EventDestinationDoesNotExist", (
        f"expected EventDestinationDoesNotExist updating a deleted destination, got {err!r}: {msg!r}"
    )
    expected_msg = f"No EventDestination found for {cfg_name}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
