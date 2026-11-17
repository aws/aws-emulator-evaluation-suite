"""create-tracking-options-unverified-domain-rejected-identically-for-missing-and-real-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tracking-options-unverified-domain-rejected-identically-for-missing-and-real-set"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetTrackingOptions refuses the same unverified redirect domain with the
    identical InvalidTrackingOptions message for a missing and a real configuration set, leaving
    the missing set not-found and the real set's TrackingOptions and Name untouched."""
    ses = ctx.client("ses")

    real_name = ctx.unique_name("sim2real-behav-cstrk-")
    ses.create_configuration_set(ConfigurationSet={"Name": real_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=real_name))

    missing_name = ctx.unique_name("sim2real-behav-cstrk-ghost-")
    redirect_domain = f"{ctx.unique_name('sim2real-behav-click-')}.example.com"

    _INVALID_TRACKING = (
        "InvalidTrackingOptions",
        f"Domain <{redirect_domain}> is not verified under this account.",
    )

    expect_error(
        lambda: ses.create_configuration_set_tracking_options(
            ConfigurationSetName=missing_name,
            TrackingOptions={"CustomRedirectDomain": redirect_domain},
        ),
        *_INVALID_TRACKING,
    )

    expect_error(
        lambda: ses.create_configuration_set_tracking_options(
            ConfigurationSetName=real_name,
            TrackingOptions={"CustomRedirectDomain": redirect_domain},
        ),
        *_INVALID_TRACKING,
    )

    _MISSING_SET = (
        "ConfigurationSetDoesNotExist",
        f"Configuration set <{missing_name}> does not exist.",
    )
    expect_error(
        lambda: ses.describe_configuration_set(ConfigurationSetName=missing_name),
        *_MISSING_SET,
    )

    described = ses.describe_configuration_set(
        ConfigurationSetName=real_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert "TrackingOptions" not in described, (
        f"the rejected Create on the real set must leave no TrackingOptions object, got "
        f"{described.get('TrackingOptions')!r}"
    )
    assert described["ConfigurationSet"]["Name"] == real_name, (
        f"the real set's own identity must be unchanged by the rejected call, got "
        f"{described['ConfigurationSet']['Name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
