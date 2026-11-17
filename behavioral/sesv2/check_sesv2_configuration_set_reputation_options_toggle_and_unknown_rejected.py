"""sesv2-configuration-set-reputation-options-toggle-and-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-configuration-set-reputation-options-toggle-and-unknown-rejected"
GROUP = "configuration-set-v2"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetReputationOptions disables then restores a real set's metrics flag,
    and the same operation on an unknown set name is refused NotFoundException, as is
    GetConfigurationSet on that name, while the real set keeps answering normally.
    """
    ses = ctx.client("sesv2")

    real_cs = ctx.unique_name("sim2real-behav-v2rep-")
    ses.create_configuration_set(ConfigurationSetName=real_cs)
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=real_cs))

    fresh = ses.get_configuration_set(ConfigurationSetName=real_cs)["ReputationOptions"]["ReputationMetricsEnabled"]
    assert fresh is True, f"expected a freshly created set to enable reputation metrics, got {fresh!r}"

    ses.put_configuration_set_reputation_options(ConfigurationSetName=real_cs, ReputationMetricsEnabled=False)
    disabled = ses.get_configuration_set(ConfigurationSetName=real_cs)["ReputationOptions"]["ReputationMetricsEnabled"]
    assert disabled is False, f"expected reputation metrics disabled, got {disabled!r}"

    ses.put_configuration_set_reputation_options(ConfigurationSetName=real_cs, ReputationMetricsEnabled=True)
    restored = ses.get_configuration_set(ConfigurationSetName=real_cs)["ReputationOptions"]["ReputationMetricsEnabled"]
    assert restored is True, f"expected reputation metrics restored to enabled, got {restored!r}"

    missing_cs = ctx.unique_name("sim2real-behav-v2rep-missing-")
    _NOT_FOUND = ("NotFoundException", f"Configuration set <{missing_cs}> does not exist.")

    put_err = _expect_error(
        lambda: ses.put_configuration_set_reputation_options(ConfigurationSetName=missing_cs, ReputationMetricsEnabled=False)
    )
    assert put_err == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {put_err!r}"

    get_err = _expect_error(lambda: ses.get_configuration_set(ConfigurationSetName=missing_cs))
    assert get_err == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {get_err!r}"

    # legal neighbour: the real set, untouched by the refused calls, still reads the state it was left in
    neighbour = ses.get_configuration_set(ConfigurationSetName=real_cs)["ReputationOptions"]["ReputationMetricsEnabled"]
    assert neighbour is True, f"expected the real set to still read enabled, got {neighbour!r}"


def _expect_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
