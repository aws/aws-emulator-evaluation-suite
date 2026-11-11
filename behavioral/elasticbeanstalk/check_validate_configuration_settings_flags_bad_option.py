"""validate-configuration-settings-flags-bad-option."""
from __future__ import annotations


from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "validate-configuration-settings-flags-bad-option"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

_STACK_CACHE = []


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) it raises. An unexpected SUCCESS
    raises, because an emulator accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _solution_stack(eb):
    """A usable SolutionStackName, preferring a current AL2023 Docker/Python stack."""
    if not _STACK_CACHE:
        _STACK_CACHE.extend(eb.list_available_solution_stacks().get("SolutionStacks") or [])
    stacks = list(_STACK_CACHE)
    if not stacks:
        raise AssertionError("No solution stacks available from ListAvailableSolutionStacks")
    preferred = (
        [s for s in stacks if "Amazon Linux 2023" in s and "running Docker" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s]
        or [s for s in stacks if "running Docker" in s]
    )
    return (preferred or stacks)[0]


def _errors_for(messages, namespace, option_name):
    """error-severity ValidationMessages scoped to one (Namespace, OptionName)."""
    return [
        m
        for m in messages
        if m.get("Severity") == "error"
        and m.get("Namespace") == namespace
        and m.get("OptionName") == option_name
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateConfigurationSettings reports one error-severity message for a non-numeric MinSize, and
    UpdateConfigurationTemplate refuses it with ConfigurationValidationException, while a numeric MinSize
    validates clean and is stored."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    ns = "aws:autoscaling:asg"
    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=_solution_stack(eb),
        OptionSettings=[{"Namespace": ns, "OptionName": "MinSize", "Value": "1"}],
    )
    ctx.on_cleanup(lambda _a=app_name, _t=template_name: eb.delete_configuration_template(ApplicationName=_a, TemplateName=_t))

    good = {"Namespace": ns, "OptionName": "MinSize", "Value": "2"}
    bad = {"Namespace": ns, "OptionName": "MinSize", "Value": "not-a-number"}

    # --- Control, established BEFORE the negative: a legal numeric value validates clean. ---
    control = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[good]
    )["Messages"]
    assert _errors_for(control, ns, "MinSize") == [], (
        f"{ns}/MinSize=2 is a legal numeric value and must produce no error-severity "
        f"ValidationMessage, got {control!r}"
    )

    # --- Break exactly one thing: a non-numeric value. ---
    messages = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[bad]
    )["Messages"]
    scoped = _errors_for(messages, ns, "MinSize")
    assert len(scoped) == 1, (
        f"a non-numeric MinSize value must produce exactly one error-severity ValidationMessage on "
        f"({ns!r}, 'MinSize'); got {messages!r}"
    )
    expected_validation_message = (
        f"Invalid option value: 'not-a-number' (Namespace: '{ns}', OptionName: 'MinSize'): "
        f"Value is not a number"
    )
    assert scoped[0]["Message"] == expected_validation_message, (
        f"expected the exact ValidationMessage text {expected_validation_message!r}, got {scoped[0]["Message"]!r}"
    )

    # --- Effect absent: the write carrying the malformed value is refused, value unchanged. ---
    code, message = _err(
        lambda: eb.update_configuration_template(
            ApplicationName=app_name, TemplateName=template_name, OptionSettings=[bad]
        )
    )
    assert code == "ConfigurationValidationException", (
        f"UpdateConfigurationTemplate with a non-numeric MinSize must be refused with "
        f"ConfigurationValidationException, got {code!r}"
    )
    expected_message = f"Configuration validation exception: {expected_validation_message}"
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )
    stored = [
        o
        for o in eb.describe_configuration_settings(
            ApplicationName=app_name, TemplateName=template_name
        )["ConfigurationSettings"][0]["OptionSettings"]
        if o.get("Namespace") == ns and o.get("OptionName") == "MinSize"
    ]
    assert len(stored) == 1 and stored[0]["Value"] == "1", (
        f"the refused update must leave the previously stored MinSize=1 intact, got {stored!r}"
    )

    # --- Control still works after the refusal. ---
    eb.update_configuration_template(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[good]
    )
    after = [
        o
        for o in eb.describe_configuration_settings(
            ApplicationName=app_name, TemplateName=template_name
        )["ConfigurationSettings"][0]["OptionSettings"]
        if o.get("Namespace") == ns and o.get("OptionName") == "MinSize"
    ]
    assert len(after) == 1 and after[0]["Value"] == "2", (
        f"after a refused update the template must still accept the legal setting, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
