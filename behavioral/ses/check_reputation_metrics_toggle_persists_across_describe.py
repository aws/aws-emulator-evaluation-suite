"""reputation-metrics-toggle-persists-across-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reputation-metrics-toggle-persists-across-describe"
GROUP = "telemetry"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Toggling UpdateConfigurationSetReputationMetricsEnabled on then off is durably
    reflected on every subsequent DescribeConfigurationSet call -- not just the response
    of the toggle call that made the change, but repeated independent reads afterwards."""
    ses = ctx.client("ses")
    cs_name = ctx.unique_name("sim2real-ses-cs-")
    ses.create_configuration_set(ConfigurationSet={"Name": cs_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=cs_name))

    def _enabled() -> bool:
        return ses.describe_configuration_set(
            ConfigurationSetName=cs_name,
            ConfigurationSetAttributeNames=["reputationOptions"],
        )["ReputationOptions"]["ReputationMetricsEnabled"]

    before = _enabled()
    assert before is False, f"expected a freshly created configuration set to default reputation metrics disabled, got {before!r}"

    ses.update_configuration_set_reputation_metrics_enabled(
        ConfigurationSetName=cs_name, Enabled=True
    )
    # Multiple independent describes, not just the immediate follow-up read.
    after_enable_1 = _enabled()
    assert after_enable_1 is True, f"describe #1 after enabling reputation metrics expected True, got {after_enable_1!r}"
    after_enable_2 = _enabled()
    assert after_enable_2 is True, f"describe #2 after enabling reputation metrics expected True, got {after_enable_2!r}"
    after_enable_3 = _enabled()
    assert after_enable_3 is True, f"describe #3 after enabling reputation metrics expected True, got {after_enable_3!r}"

    ses.update_configuration_set_reputation_metrics_enabled(
        ConfigurationSetName=cs_name, Enabled=False
    )
    after_disable_1 = _enabled()
    assert after_disable_1 is False, f"describe #1 after disabling reputation metrics expected False, got {after_disable_1!r}"
    after_disable_2 = _enabled()
    assert after_disable_2 is False, f"describe #2 after disabling reputation metrics expected False, got {after_disable_2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
