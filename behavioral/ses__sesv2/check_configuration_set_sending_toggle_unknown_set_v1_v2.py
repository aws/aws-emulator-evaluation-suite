"""configuration-set-sending-toggle-unknown-set-v1-v2."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-sending-toggle-unknown-set-v1-v2"
GROUP = "shared-state-v1-v2"
SERVICES = ["ses", "sesv2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """Return the rejected call's (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SESv1 UpdateConfigurationSetSendingEnabled and SESv2 PutConfigurationSetSendingOptions
    each refuse the same nonexistent configuration set with their own exact error.
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    ghost_name = ctx.unique_name("sim2real-behav-cssend-ghost-")

    v1_err = _error(lambda: v1.update_configuration_set_sending_enabled(ConfigurationSetName=ghost_name, Enabled=False))
    assert v1_err == ("Throttling", f"Update conflict when updating configuration set <{ghost_name}>."), (
        f"expected v1 UpdateConfigurationSetSendingEnabled on an unknown set to answer "
        f"Throttling with the exact update-conflict message, got {v1_err!r}"
    )

    v2_err = _error(lambda: v2.put_configuration_set_sending_options(ConfigurationSetName=ghost_name, SendingEnabled=False))
    assert v2_err == ("NotFoundException", f"Configuration set <{ghost_name}> does not exist."), (
        f"expected v2 PutConfigurationSetSendingOptions on an unknown set to answer "
        f"NotFoundException naming it, got {v2_err!r}"
    )

    # Effect absent: neither rejected call implicitly created the configuration set.
    describe_err = _error(lambda: v1.describe_configuration_set(ConfigurationSetName=ghost_name))
    assert describe_err == ("ConfigurationSetDoesNotExist", f"Configuration set <{ghost_name}> does not exist."), (
        f"the two rejected toggles left a configuration set describable: {describe_err!r}"
    )
    get_err = _error(lambda: v2.get_configuration_set(ConfigurationSetName=ghost_name))
    assert get_err == ("NotFoundException", f"Configuration set <{ghost_name}> does not exist."), (
        f"the two rejected toggles left a configuration set gettable via v2: {get_err!r}"
    )

    # Positive control: the identical v1 toggle against a real configuration set succeeds and
    # is visible via v2 GetConfigurationSet.
    real_name = ctx.unique_name("sim2real-behav-cssend-real-")
    v2.create_configuration_set(ConfigurationSetName=real_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: v2.delete_configuration_set(ConfigurationSetName=real_name), "NotFoundException"))

    v1.update_configuration_set_sending_enabled(ConfigurationSetName=real_name, Enabled=False)
    got = v2.get_configuration_set(ConfigurationSetName=real_name)
    assert got["ConfigurationSetName"] == real_name, f"expected {real_name!r}, got {got['ConfigurationSetName']!r}"
    assert got["SendingOptions"]["SendingEnabled"] is False, (
        f"positive control failed: v1 UpdateConfigurationSetSendingEnabled(False) on a real set "
        f"was not reflected by v2, got {got['SendingOptions']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
