"""update-configuration-set-tracking-options-missing-tracking-options-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-configuration-set-tracking-options-missing-tracking-options-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a set with no TrackingOptions, the Update call fails with InvalidTrackingOptions (unverified
    domain) and Delete fails with TrackingOptionsDoesNotExist; neither creates TrackingOptions."""
    ses = ctx.client("ses")
    config_set_name = ctx.unique_name("sim2real-ses-cfgset-")
    ses.create_configuration_set(ConfigurationSet={"Name": config_set_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=config_set_name))

    # UpdateConfigurationSetTrackingOptions requires a CustomRedirectDomain; any domain we can
    # supply here is unverified, so the call fails with InvalidTrackingOptions rather than ever
    # reaching a "no TrackingOptions object" check.
    probe_domain = f"{ctx.unique_name('sim2real-ses-track0-')}.example.com"
    update_code = _error_code(
        lambda: ses.update_configuration_set_tracking_options(
            ConfigurationSetName=config_set_name,
            TrackingOptions={"CustomRedirectDomain": probe_domain},
        )
    )
    assert update_code == (
        "InvalidTrackingOptions",
        f"Domain <{probe_domain}> is not verified under this account.",
    ), f"expected InvalidTrackingOptions, got {update_code!r}"

    # DeleteConfigurationSetTrackingOptions has no domain to validate, so it surfaces the
    # underlying "no TrackingOptions object exists" condition directly.
    delete_code = _error_code(
        lambda: ses.delete_configuration_set_tracking_options(
            ConfigurationSetName=config_set_name
        )
    )
    assert delete_code == (
        "TrackingOptionsDoesNotExist",
        f"There are no tracking options for configuration set <{config_set_name}>",
    ), f"expected TrackingOptionsDoesNotExist, got {delete_code!r}"

    described = ses.describe_configuration_set(
        ConfigurationSetName=config_set_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert not described.get("TrackingOptions"), (
        "rejected calls left a TrackingOptions object on a configuration set that had none"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is None:
            raise
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

