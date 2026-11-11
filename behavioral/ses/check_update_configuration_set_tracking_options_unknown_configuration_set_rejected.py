"""update-configuration-set-tracking-options-unknown-configuration-set-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-configuration-set-tracking-options-unknown-configuration-set-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tracking-options calls on a missing configuration set fail without creating it: Update fails the
    domain check first, Delete reports ConfigurationSetDoesNotExist, and Delete on a real set without
    tracking options reports TrackingOptionsDoesNotExist."""
    ses = ctx.client("ses")
    missing_name = ctx.unique_name("sim2real-ses-cfgset-missing-")

    probe_domain = f"{ctx.unique_name('sim2real-ses-track0-')}.example.com"
    update_code = _error_code(
        lambda: ses.update_configuration_set_tracking_options(
            ConfigurationSetName=missing_name,
            TrackingOptions={"CustomRedirectDomain": probe_domain},
        )
    )
    assert update_code == (
        "InvalidTrackingOptions",
        f"Domain <{probe_domain}> is not verified under this account.",
    ), f"expected InvalidTrackingOptions, got {update_code!r}"

    # Delete has no domain to validate, so it surfaces the missing configuration set directly.
    delete_code = _error_code(
        lambda: ses.delete_configuration_set_tracking_options(ConfigurationSetName=missing_name)
    )
    assert delete_code == (
        "ConfigurationSetDoesNotExist",
        f"Configuration set <{missing_name}> does not exist.",
    ), f"expected ConfigurationSetDoesNotExist, got {delete_code!r}"

    describe_code = _error_code(
        lambda: ses.describe_configuration_set(ConfigurationSetName=missing_name)
    )
    assert describe_code == (
        "ConfigurationSetDoesNotExist",
        f"Configuration set <{missing_name}> does not exist.",
    ), (
        f"rejected calls against a missing configuration set left it describable "
        f"(describe returned code {describe_code!r})"
    )

    real_name = ctx.unique_name("sim2real-ses-cfgset-real-")
    ses.create_configuration_set(ConfigurationSet={"Name": real_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=real_name))
    real_delete_code = _error_code(
        lambda: ses.delete_configuration_set_tracking_options(ConfigurationSetName=real_name)
    )
    assert real_delete_code == (
        "TrackingOptionsDoesNotExist",
        f"There are no tracking options for configuration set <{real_name}>",
    ), (
        f"expected TrackingOptionsDoesNotExist for a real configuration set with no tracking "
        f"options, got {real_delete_code!r}"
    )

    real_described = ses.describe_configuration_set(
        ConfigurationSetName=real_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert not real_described.get("TrackingOptions"), (
        f"rejected delete on a real configuration set left a TrackingOptions object: "
        f"{real_described.get('TrackingOptions')}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is None:
            raise
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

