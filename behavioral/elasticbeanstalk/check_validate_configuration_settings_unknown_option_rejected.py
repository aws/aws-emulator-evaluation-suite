"""validate-configuration-settings-unknown-option-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "validate-configuration-settings-unknown-option-rejected"
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


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unknown option name inside a real namespace (aws:autoscaling:asg) gets an error-severity
    ValidationMessage and is not in the published catalog, the write is refused and stores nothing,
    and a real option in the same namespace still validates and writes.
    """
    eb = ctx.client("elasticbeanstalk")
    tag = [{"Key": "sim2real", "Value": "eb-validate-unknown-option"}]
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    stack = _solution_stack(eb)
    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        Tags=tag,
    )
    ctx.on_cleanup(
        lambda _a=app_name, _t=template_name: eb.delete_configuration_template(
            ApplicationName=_a, TemplateName=_t
        )
    )

    namespace = "aws:autoscaling:asg"
    bogus_option = "NotAnOptionInThisNamespace"
    good = {"Namespace": namespace, "OptionName": "MinSize", "Value": "2"}
    bad = {"Namespace": namespace, "OptionName": bogus_option, "Value": "2"}

    # --- The published catalog must agree that the option does not exist. ---
    catalog = eb.describe_configuration_options(SolutionStackName=stack)["Options"]
    ns_options = {o["Name"] for o in catalog if o.get("Namespace") == namespace}
    assert "MinSize" in ns_options, (
        f"{namespace} must publish MinSize in DescribeConfigurationOptions, got {sorted(ns_options)!r}"
    )
    assert bogus_option not in ns_options, (
        f"{bogus_option!r} must not be a described option of {namespace}, got {sorted(ns_options)!r}"
    )

    # --- Control, established BEFORE the negative. ---
    control = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[good]
    )["Messages"]
    control_errors = [m for m in control if m.get("Severity") == "error"]
    assert control_errors == [], (
        f"{namespace}/MinSize=2 is a legal setting and must produce no error-severity "
        f"ValidationMessage, got {control_errors!r}"
    )

    # --- Break exactly one thing: the option name. ---
    messages = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[bad]
    )["Messages"]
    scoped = _errors_for(messages, namespace, bogus_option)
    assert len(scoped) == 1, (
        f"exactly one error-severity ValidationMessage must be attributed to "
        f"({namespace!r}, {bogus_option!r}); got {messages!r}"
    )
    assert scoped[0]["Namespace"] == namespace, scoped[0]
    assert scoped[0]["OptionName"] == bogus_option, (
        f"the ValidationMessage must name the unknown option, got {scoped[0]['OptionName']!r}"
    )
    expected_validation_message = (
        f"Invalid option specification (Namespace: '{namespace}', OptionName: '{bogus_option}'): "
        f"Unknown configuration setting."
    )
    assert scoped[0]["Message"] == expected_validation_message, (
        f"expected the exact ValidationMessage text {expected_validation_message!r}, got {scoped[0]["Message"]!r}"
    )

    # --- Effect absent. ---
    code, message = _err(
        lambda: eb.update_configuration_template(
            ApplicationName=app_name, TemplateName=template_name, OptionSettings=[bad]
        )
    )
    # On real AWS: a write that carries a setting the
    # validation engine rejects comes back as ConfigurationValidationException (HTTP 400) whose
    # message is "Configuration validation exception: " + the ValidationMessage text above. The
    # code is NOT a modeled Smithy error shape on UpdateConfigurationTemplate (the model lists
    # only InsufficientPrivilegesException / TooManyBucketsException), so it can only be pinned
    # from observation.
    assert code == "ConfigurationValidationException", (
        f"UpdateConfigurationTemplate with an unknown option in a known namespace must be refused "
        f"with ConfigurationValidationException, got {code!r}"
    )
    expected_message = f"Configuration validation exception: {expected_validation_message}"
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]["OptionSettings"]
    assert not [o for o in settings if o.get("OptionName") == bogus_option], (
        f"the refused option must not appear in the stored template settings; "
        f"found {[o for o in settings if o.get('OptionName') == bogus_option]!r}"
    )

    # --- Control still works after the refusal. ---
    eb.update_configuration_template(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[good]
    )
    after = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]["OptionSettings"]
    min_size = [
        o for o in after if o.get("Namespace") == namespace and o.get("OptionName") == "MinSize"
    ]
    assert len(min_size) == 1 and min_size[0]["Value"] == "2", (
        f"after a refused update the template must still accept the legal setting, got {min_size!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
