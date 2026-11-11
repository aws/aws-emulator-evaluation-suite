"""update-configuration-set-tracking-options-invalid-custom-redirect-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-configuration-set-tracking-options-invalid-custom-redirect-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Create/UpdateConfigurationSetTrackingOptions reject a malformed or unverified
    CustomRedirectDomain with InvalidTrackingOptions and leave the set without TrackingOptions."""
    ses = ctx.client("ses")
    config_set_name = ctx.unique_name("sim2real-ses-cfgset-")
    ses.create_configuration_set(ConfigurationSet={"Name": config_set_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=config_set_name))

    described0 = ses.describe_configuration_set(
        ConfigurationSetName=config_set_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert not described0.get("TrackingOptions"), (
        "freshly created configuration set unexpectedly already has tracking options"
    )

    # URL scheme plus an illegal double-dot label.
    malformed_domain = "http://bad_domain..example.com"
    create_code = _error_code(
        lambda: ses.create_configuration_set_tracking_options(
            ConfigurationSetName=config_set_name,
            TrackingOptions={"CustomRedirectDomain": malformed_domain},
        )
    )
    assert create_code == (
        "InvalidTrackingOptions",
        f"Domain <{malformed_domain}> is not a valid domain.",
    ), f"expected InvalidTrackingOptions from Create, got {create_code!r}"

    # Domain validation runs ahead of the TrackingOptions object's existence check.
    update_code = _error_code(
        lambda: ses.update_configuration_set_tracking_options(
            ConfigurationSetName=config_set_name,
            TrackingOptions={"CustomRedirectDomain": malformed_domain},
        )
    )
    assert update_code == (
        "InvalidTrackingOptions",
        f"Domain <{malformed_domain}> is not a valid domain.",
    ), f"expected InvalidTrackingOptions from Update, got {update_code!r}"

    # Domain ownership is checked too, not only syntax.
    unverified_domain = f"{ctx.unique_name('sim2real-ses-track-')}.example.com"
    unverified_code = _error_code(
        lambda: ses.create_configuration_set_tracking_options(
            ConfigurationSetName=config_set_name,
            TrackingOptions={"CustomRedirectDomain": unverified_domain},
        )
    )
    assert unverified_code == (
        "InvalidTrackingOptions",
        f"Domain <{unverified_domain}> is not verified under this account.",
    ), (
        f"expected InvalidTrackingOptions for an unverified (but well-formed) domain, "
        f"got {unverified_code!r}"
    )

    described1 = ses.describe_configuration_set(
        ConfigurationSetName=config_set_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert not described1.get("TrackingOptions"), (
        "rejected Create/Update calls left a TrackingOptions object on the configuration set"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is not None:
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


