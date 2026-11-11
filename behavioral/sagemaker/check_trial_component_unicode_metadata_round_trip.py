"""trial-component-unicode-metadata-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-component-unicode-metadata-round-trip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trial component's unicode string parameter and numeric parameter describe unchanged, while a
    unicode DisplayName is refused with ValidationException (exact message) and leaves no component
    behind (DescribeTrialComponent: ResourceNotFound, exact message).
    """
    sm = ctx.client("sagemaker")

    name = ctx.unique_name("sim2real-behav-tc-")
    valid_display_name = "control-display-name"
    param_string_value = "établi-値-Ω-string-with-\"quotes\"-and-\\backslash\\"

    sm.create_trial_component(
        TrialComponentName=name,
        DisplayName=valid_display_name,
        Parameters={
            "unicode_param": {"StringValue": param_string_value},
            "numeric_param": {"NumberValue": 3.0},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))

    desc = sm.describe_trial_component(TrialComponentName=name)

    assert desc["DisplayName"] == valid_display_name, (
        f"DisplayName mangled: expected {valid_display_name!r} got {desc['DisplayName']!r}"
    )
    params = desc["Parameters"]
    assert params["unicode_param"]["StringValue"] == param_string_value, (
        "unicode StringValue parameter mangled on round-trip: "
        f"expected {param_string_value!r} got {params['unicode_param'].get('StringValue')!r}"
    )
    assert params["numeric_param"]["NumberValue"] == 3.0, (
        f"expected numeric_param NumberValue 3.0, got {params['numeric_param'].get('NumberValue')!r}"
    )

    # Negative: a Unicode DisplayName violates ExperimentEntityName's ASCII pattern and must be
    # rejected outright -- an always-invalid input, so there is no restore leg by construction.
    # The positive control above already proves CreateTrialComponent otherwise works.
    unicode_display_name = "実験-component-Ünïcødé-☂-emoji-🚀-name"
    rejected_name = ctx.unique_name("sim2real-behav-tc-rej-")
    try:
        sm.create_trial_component(TrialComponentName=rejected_name, DisplayName=unicode_display_name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for a Unicode DisplayName, got {code!r}: {err}"
        )
        expected_message = (
            f"1 validation error detected: Value '{unicode_display_name}' at 'displayName' failed "
            "to satisfy constraint: Member must satisfy regular expression pattern: "
            "[a-zA-Z0-9](-*[a-zA-Z0-9]){0,119}"
        )
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=rejected_name))
        raise AssertionError(
            f"expected CreateTrialComponent to reject Unicode DisplayName {unicode_display_name!r}, "
            "but it was accepted"
        )

    # Effect absent: the rejected call never left anything behind for an independent read to find.
    try:
        sm.describe_trial_component(TrialComponentName=rejected_name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFound", (
            f"expected ResourceNotFound for the never-created component, got {code!r}: {err}"
        )
        rejected_arn = (
            f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial-component/{rejected_name}"
        )
        expected_message = f"Trial component '{rejected_arn}' does not exist."
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            f"trial component {rejected_name!r} exists despite its create being rejected"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
