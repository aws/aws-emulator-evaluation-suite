"""v1-reputation-metrics-crossapi-and-unknown-set-refused."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "v1-reputation-metrics-crossapi-and-unknown-set-refused"
GROUP = "configuration-set"
SERVICES = ["ses"]


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message); an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationSetReputationMetricsEnabled(true) on a v1-created set reads true through
    both v1 DescribeConfigurationSet and SESv2 GetConfigurationSet (false before); on an unknown
    set it is refused Throttling, and that set's v1 Describe is refused ConfigurationSetDoesNotExist.
    """
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")

    name = ctx.unique_name("sim2real-behav-v1rep-")
    ses.create_configuration_set(ConfigurationSet={"Name": name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=name))

    def _v1_enabled():
        return ses.describe_configuration_set(
            ConfigurationSetName=name, ConfigurationSetAttributeNames=["reputationOptions"]
        )["ReputationOptions"]["ReputationMetricsEnabled"]

    def _v2_enabled():
        return sesv2.get_configuration_set(ConfigurationSetName=name)["ReputationOptions"]["ReputationMetricsEnabled"]

    v1_before, v2_before = _v1_enabled(), _v2_enabled()
    assert (v1_before, v2_before) == (False, False), (
        f"expected both APIs to read reputation metrics disabled before the update, "
        f"got v1={v1_before!r}, v2={v2_before!r}"
    )

    ses.update_configuration_set_reputation_metrics_enabled(ConfigurationSetName=name, Enabled=True)

    v1_after, v2_after = _v1_enabled(), _v2_enabled()
    assert (v1_after, v2_after) == (True, True), (
        f"expected both APIs to read reputation metrics enabled after the update, "
        f"got v1={v1_after!r}, v2={v2_after!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-v1rep-ghost-")
    _UPDATE_CONFLICT = ("Throttling", f"Update conflict when updating configuration set <{ghost}>.")
    expect_error(
        lambda: ses.update_configuration_set_reputation_metrics_enabled(ConfigurationSetName=ghost, Enabled=True),
        *_UPDATE_CONFLICT,
    )

    _DOES_NOT_EXIST = ("ConfigurationSetDoesNotExist", f"Configuration set <{ghost}> does not exist.")
    expect_error(
        lambda: ses.describe_configuration_set(ConfigurationSetName=ghost),
        *_DOES_NOT_EXIST,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
