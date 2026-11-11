"""event-destination-on-missing-configuration-set-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destination-on-missing-configuration-set-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating or deleting an event destination on an absent configuration set fails with
    ConfigurationSetDoesNotExist without recreating the set; both succeed on a real set."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-absent-")
    dest_name = "dest"
    cw = {
        "DimensionConfigurations": [
            {
                "DimensionName": "ses:configuration-set",
                "DimensionValueSource": "messageTag",
                "DefaultDimensionValue": "none",
            }
        ]
    }
    destination = {
        "Name": dest_name,
        "Enabled": True,
        "MatchingEventTypes": ["send"],
        "CloudWatchDestination": cw,
    }

    def _create():
        return ses.create_configuration_set_event_destination(
            ConfigurationSetName=cfg_name, EventDestination=destination
        )

    def _delete():
        return ses.delete_configuration_set_event_destination(
            ConfigurationSetName=cfg_name, EventDestinationName=dest_name
        )

    # Positive control: against a REAL configuration set with this exact name, both calls
    # succeed, so the later rejection cannot be "every create/delete call fails".
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=cfg_name))
    _create()
    _delete()

    # Break exactly one thing: remove the configuration set itself.
    ses.delete_configuration_set(ConfigurationSetName=cfg_name)

    expected_msg = f"Configuration set <{cfg_name}> does not exist."
    err, msg = _err(_create)
    assert err == "ConfigurationSetDoesNotExist", (
        f"expected ConfigurationSetDoesNotExist attaching to an absent set, got {err!r}: {msg!r}"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Deleting an event destination from an absent configuration set fails the same way.
    err2, msg2 = _err(_delete)
    assert err2 == "ConfigurationSetDoesNotExist", (
        f"expected ConfigurationSetDoesNotExist deleting from an absent set, got {err2!r}: {msg2!r}"
    )
    assert msg2 == expected_msg, f"expected message {expected_msg!r}, got {msg2!r}"

    # Effect absent: neither rejected call conjured the configuration set back into existence.
    describe_err, describe_msg = _err(
        lambda: ses.describe_configuration_set(ConfigurationSetName=cfg_name)
    )
    assert describe_err == "ConfigurationSetDoesNotExist", (
        f"rejected calls against a missing configuration set left it describable "
        f"(describe returned code {describe_err!r}: {describe_msg!r})"
    )
    assert describe_msg == expected_msg, f"expected message {expected_msg!r}, got {describe_msg!r}"

    # Restore: recreate the identically-named configuration set, and the identical call that
    # was just rejected now succeeds again.
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    _create()

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
