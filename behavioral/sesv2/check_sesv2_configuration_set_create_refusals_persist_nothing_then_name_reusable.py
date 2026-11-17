"""sesv2-configuration-set-create-refusals-persist-nothing-then-name-reusable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-configuration-set-create-refusals-persist-nothing-then-name-reusable"
GROUP = "configuration-set-v2"
SERVICES = ["sesv2"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _list_all_names(ses):
    names = []
    kwargs = {}
    while True:
        page = ses.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            return names
        kwargs["NextToken"] = token


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSet refuses a syntactically invalid name, and separately refuses a
    valid name paired with an unverified tracking domain; neither refusal persists a set, and
    the same name then creates cleanly without TrackingOptions.
    """
    ses = ctx.client("sesv2")

    _BAD_NAME = (
        "BadRequestException",
        "Invalid configuration set name <bad name!>: only alphanumeric ASCII characters, "
        "'_', and '-' are allowed.",
    )
    expect_error(lambda: ses.create_configuration_set(ConfigurationSetName="bad name!"), *_BAD_NAME)
    names = _list_all_names(ses)
    assert "bad name!" not in names, f"a rejected invalid-name create still persisted a set, got {names!r}"

    name = ctx.unique_name("sim2real-behav-v2csreuse-")
    domain = f"click.{ctx.unique_name('sim2real-behav-probe-')}.example.com"
    _UNVERIFIED_DOMAIN = ("BadRequestException", f"Domain <{domain}> is not verified under this account.")
    expect_error(
        lambda: ses.create_configuration_set(
            ConfigurationSetName=name,
            TrackingOptions={"CustomRedirectDomain": domain, "HttpsPolicy": "REQUIRE"},
        ),
        *_UNVERIFIED_DOMAIN,
    )
    _NOT_FOUND = ("NotFoundException", f"Configuration set <{name}> does not exist.")
    expect_error(lambda: ses.get_configuration_set(ConfigurationSetName=name), *_NOT_FOUND)

    # Legal neighbour: the same name, without TrackingOptions, creates and reads back clean.
    ses.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=name))
    got = ses.get_configuration_set(ConfigurationSetName=name)
    assert got["ConfigurationSetName"] == name, (
        f"expected ConfigurationSetName {name!r}, got {got.get('ConfigurationSetName')!r}"
    )
    assert got.get("TrackingOptions") is None, f"expected no TrackingOptions, got {got.get('TrackingOptions')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
