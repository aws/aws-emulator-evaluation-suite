"""validate-configuration-settings-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "validate-configuration-settings-out-of-range-rejected"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "plane:control")
def run(ctx) -> None:
    """ValidateConfigurationSettings reports a Severity=error message for an option value outside its MinValue/MaxValue
    range and none for an in-range value, and neither call changes the template's stored setting."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-validate-")
    template_name = ctx.unique_name("sim2real-tmpl-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: eb.delete_configuration_template(ApplicationName=app_name, TemplateName=template_name))

    options = eb.describe_configuration_options(ApplicationName=app_name, TemplateName=template_name)["Options"]
    candidate = next(
        o for o in options if o.get("ValueType") == "Scalar" and o.get("MaxValue") is not None
    )
    namespace, option_name = candidate["Namespace"], candidate["Name"]
    min_value = candidate.get("MinValue", 0)
    max_value = candidate["MaxValue"]
    valid_value = str((min_value + max_value) // 2)
    invalid_value = str(max_value + 1_000_000)

    original_settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]["OptionSettings"]
    original_value = next(
        s["Value"] for s in original_settings if s["Namespace"] == namespace and s["OptionName"] == option_name
    )

    # Positive control: a value inside [MinValue, MaxValue] is not flagged.
    ok_messages = eb.validate_configuration_settings(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[{"Namespace": namespace, "OptionName": option_name, "Value": valid_value}],
    )["Messages"]
    assert not any(
        m["Namespace"] == namespace and m["OptionName"] == option_name and m["Severity"] == "error"
        for m in ok_messages
    ), (
        f"{namespace}/{option_name}={valid_value} is inside the published range "
        f"[{min_value}, {max_value}] and must not produce an error-severity ValidationMessage, "
        f"got {ok_messages!r}"
    )

    # Negative: a value far outside the documented range is flagged as an error.
    bad_messages = eb.validate_configuration_settings(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[{"Namespace": namespace, "OptionName": option_name, "Value": invalid_value}],
    )["Messages"]
    assert any(
        m["Namespace"] == namespace and m["OptionName"] == option_name and m["Severity"] == "error"
        for m in bad_messages
    ), (
        f"{namespace}/{option_name}={invalid_value} is past the published MaxValue {max_value} and "
        f"must produce an error-severity ValidationMessage on that exact (Namespace, OptionName), "
        f"got {bad_messages!r}"
    )

    # Effect absent: neither call persisted anything to the template.
    final_settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]["OptionSettings"]
    final_value = next(
        s["Value"] for s in final_settings if s["Namespace"] == namespace and s["OptionName"] == option_name
    )
    assert final_value == original_value, (
        f"neither ValidateConfigurationSettings call may persist to the template's stored "
        f"settings; expected {namespace}/{option_name} to remain {original_value!r}, got "
        f"{final_value!r}"
    )


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
