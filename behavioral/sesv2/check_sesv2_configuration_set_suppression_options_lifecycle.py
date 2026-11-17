"""sesv2-configuration-set-suppression-options-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-configuration-set-suppression-options-lifecycle"
GROUP = "configuration-set-v2"
SERVICES = ["sesv2"]

_INVALID_REASON = (
    "BadRequestException",
    "Reason INVALID is invalid, must be one of [BOUNCE, COMPLAINT].",
)


def expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert err == (code, message), f"expected {(code, message)!r}, got {err!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetSuppressionOptions rejects an unknown reason with an unchanged, absent
    SuppressionOptions on a fresh set, then an empty list reads back exactly [] rather than absent
    or the prior value, and the same call on an unknown configuration set is refused by name.
    """
    ses = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-v2sup-")
    ses.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))

    fresh = ses.get_configuration_set(ConfigurationSetName=name).get("SuppressionOptions")
    assert fresh is None, f"expected a fresh configuration set to carry no SuppressionOptions, got {fresh!r}"

    expect_error(
        lambda: ses.put_configuration_set_suppression_options(ConfigurationSetName=name, SuppressedReasons=["INVALID"]),
        *_INVALID_REASON,
    )
    after_invalid = ses.get_configuration_set(ConfigurationSetName=name).get("SuppressionOptions")
    assert after_invalid == fresh, f"expected SuppressionOptions unchanged at {fresh!r}, got {after_invalid!r}"

    ses.put_configuration_set_suppression_options(ConfigurationSetName=name, SuppressedReasons=["BOUNCE"])
    bounce = ses.get_configuration_set(ConfigurationSetName=name)["SuppressionOptions"]["SuppressedReasons"]
    assert bounce == ["BOUNCE"], f"expected [BOUNCE], got {bounce!r}"

    ses.put_configuration_set_suppression_options(ConfigurationSetName=name, SuppressedReasons=[])
    cleared = ses.get_configuration_set(ConfigurationSetName=name)["SuppressionOptions"]["SuppressedReasons"]
    assert cleared == [], f"expected an explicit empty list, neither absent nor [BOUNCE], got {cleared!r}"

    missing = ctx.unique_name("sim2real-behav-v2sup-missing-")
    _unknown_set = ("NotFoundException", f"Configuration set <{missing}> does not exist.")
    expect_error(
        lambda: ses.put_configuration_set_suppression_options(ConfigurationSetName=missing, SuppressedReasons=["BOUNCE"]),
        *_unknown_set,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
