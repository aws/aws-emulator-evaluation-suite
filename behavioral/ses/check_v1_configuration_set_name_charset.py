"""v1-configuration-set-name-charset."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "v1-configuration-set-name-charset"
GROUP = "configuration-set"
SERVICES = ["ses"]


def expect_error(fn, code, message):
    """Run ``fn``; require it to raise a ClientError matching ``(code, message)`` exactly."""
    try:
        outcome = fn()
    except ClientError as exc:
        actual = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return
    raise AssertionError(f"expected ({code}, {message!r}) but the call returned {outcome!r}")


def _names_on_record(ses) -> set:
    pages = ses.get_paginator("list_configuration_sets").paginate()
    return {entry["Name"] for page in pages for entry in page["ConfigurationSets"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SESv1 CreateConfigurationSet refuses a name holding a character outside
    [A-Za-z0-9_-], creates nothing for it, and accepts a name that mixes '_' and '-'.
    """
    ses = ctx.client("ses")

    stray_char_name = ctx.unique_name("sim2real-behav-cfgset-charset-") + "+1"
    _REFUSAL = (
        "InvalidParameterValue",
        f"Invalid configuration set name <{stray_char_name}>: only alphanumeric ASCII "
        "characters, '_', and '-' are allowed.",
    )
    expect_error(lambda: ses.create_configuration_set(
        ConfigurationSet={"Name": stray_char_name}
    ), *_REFUSAL)
    on_record = _names_on_record(ses)
    assert stray_char_name not in on_record, (
        f"{stray_char_name!r} was refused but still appears in ListConfigurationSets"
    )

    mixed_name = ctx.unique_name("sim2real-behav-cfgset-charset_") + "-mix"
    ses.create_configuration_set(ConfigurationSet={"Name": mixed_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=mixed_name))
    described = ses.describe_configuration_set(ConfigurationSetName=mixed_name)
    assert described["ConfigurationSet"]["Name"] == mixed_name, (
        f"expected DescribeConfigurationSet to return {mixed_name!r}, "
        f"got {described['ConfigurationSet']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
