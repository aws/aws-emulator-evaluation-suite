"""event-destination-delete-twice-refused-with-attribute-gated-reads."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destination-delete-twice-refused-with-attribute-gated-reads"
GROUP = "configuration-set"
SERVICES = ["ses"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationSet returns event destinations only when eventDestinations is
    requested; once DeleteConfigurationSetEventDestination removes the one destination, a
    second delete of that name is refused EventDestinationDoesNotExist.
    """
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-eddel2-")
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

    without_attr = ses.describe_configuration_set(ConfigurationSetName=cfg_name)
    assert without_attr.get("EventDestinations", []) == [], (
        f"expected no event destinations without requesting the attribute, got "
        f"{without_attr.get('EventDestinations')!r}"
    )

    with_attr = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    ).get("EventDestinations", [])
    assert [d["Name"] for d in with_attr] == [dest_name], (
        f"expected exactly [{dest_name!r}] with the attribute requested, got "
        f"{[d['Name'] for d in with_attr]!r}"
    )

    ses.delete_configuration_set_event_destination(
        ConfigurationSetName=cfg_name, EventDestinationName=dest_name
    )

    after_delete = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    ).get("EventDestinations", [])
    assert after_delete == [], (
        f"expected no event destinations after delete, got {after_delete!r}"
    )

    expected = ("EventDestinationDoesNotExist", f"No EventDestination found for {cfg_name}")
    expect_error(
        lambda: ses.delete_configuration_set_event_destination(
            ConfigurationSetName=cfg_name, EventDestinationName=dest_name
        ),
        *expected,
    )

    after_second_delete = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["eventDestinations"]
    ).get("EventDestinations", [])
    assert after_second_delete == [], (
        f"expected no event destinations after the refused second delete, got "
        f"{after_second_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
