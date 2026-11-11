"""reputation-metrics-flag-isolated-per-configuration-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reputation-metrics-flag-isolated-per-configuration-set"
GROUP = "server-side"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling reputation metrics on one configuration set must not leak onto a
    sibling configuration set's ReputationOptions.ReputationMetricsEnabled flag."""
    ses = ctx.client("ses")
    cs_a = ctx.unique_name("sim2real-ses-cs-a-")
    cs_b = ctx.unique_name("sim2real-ses-cs-b-")

    ses.create_configuration_set(ConfigurationSet={"Name": cs_a})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=cs_a))
    ses.create_configuration_set(ConfigurationSet={"Name": cs_b})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=cs_b))

    # Both start disabled by default.
    desc_a0 = ses.describe_configuration_set(
        ConfigurationSetName=cs_a, ConfigurationSetAttributeNames=["reputationOptions"]
    )
    desc_b0 = ses.describe_configuration_set(
        ConfigurationSetName=cs_b, ConfigurationSetAttributeNames=["reputationOptions"]
    )
    a0 = desc_a0["ReputationOptions"]["ReputationMetricsEnabled"]
    b0 = desc_b0["ReputationOptions"]["ReputationMetricsEnabled"]
    assert a0 is False, f"expected freshly created set A to default reputation metrics disabled, got {a0!r}"
    assert b0 is False, f"expected freshly created set B to default reputation metrics disabled, got {b0!r}"

    ses.update_configuration_set_reputation_metrics_enabled(
        ConfigurationSetName=cs_a, Enabled=True
    )

    desc_a1 = ses.describe_configuration_set(
        ConfigurationSetName=cs_a, ConfigurationSetAttributeNames=["reputationOptions"]
    )
    desc_b1 = ses.describe_configuration_set(
        ConfigurationSetName=cs_b, ConfigurationSetAttributeNames=["reputationOptions"]
    )
    a1 = desc_a1["ReputationOptions"]["ReputationMetricsEnabled"]
    b1 = desc_b1["ReputationOptions"]["ReputationMetricsEnabled"]
    assert a1 is True, f"expected set A to read reputation metrics enabled after the toggle, got {a1!r}"
    assert b1 is False, (
        f"toggling reputation metrics on configuration set A leaked onto sibling set B: expected B "
        f"to stay disabled, got {b1!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
