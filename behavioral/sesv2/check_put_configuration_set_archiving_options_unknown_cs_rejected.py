"""put-configuration-set-archiving-options-unknown-cs-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-configuration-set-archiving-options-unknown-cs-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetArchivingOptions against a non-existent configuration set raises NotFoundException."""
    ses = ctx.client("sesv2")

    missing_cs = ctx.unique_name("sim2real-nocs-")

    expected = ("NotFoundException", f"Configuration set <{missing_cs}> does not exist.")
    err = _error(
        lambda: ses.put_configuration_set_archiving_options(ConfigurationSetName=missing_cs)
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # Effect absent: no configuration set was implicitly created by the rejected call.
    get_err = _error(
        lambda: ses.get_configuration_set(ConfigurationSetName=missing_cs)
    )
    assert get_err == expected, f"expected {expected!r}, got {get_err!r}"

    # Positive control: the exact same call against a real configuration set succeeds.
    real_cs = ctx.unique_name("sim2real-cs-")
    ses.create_configuration_set(ConfigurationSetName=real_cs)
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=real_cs))

    ses.put_configuration_set_archiving_options(ConfigurationSetName=real_cs)
    got = ses.get_configuration_set(ConfigurationSetName=real_cs)
    assert got["ConfigurationSetName"] == real_cs, (
        f"expected the positive control's ConfigurationSetName to be {real_cs!r}, got "
        f"{got['ConfigurationSetName']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
