"""validate-configuration-settings-enforces-published-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "validate-configuration-settings-enforces-published-range-rejected"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

_STACK_CACHE = []


def _err(fn):
    """Return the (Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
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


def _described(catalog, namespace, name):
    """The single ConfigurationOptionDescription for (namespace, name)."""
    hits = [o for o in catalog if o.get("Namespace") == namespace and o.get("Name") == name]
    assert len(hits) == 1, (
        f"DescribeConfigurationOptions must describe exactly one ({namespace!r}, {name!r}) option, "
        f"got {hits!r}"
    )
    return hits[0]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateConfigurationSettings and UpdateConfigurationTemplate reject a MaxSize one past the
    MaxValue DescribeConfigurationOptions publishes, while both published boundaries are accepted."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    stack = _solution_stack(eb)
    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda _a=app_name, _t=template_name: eb.delete_configuration_template(
            ApplicationName=_a, TemplateName=_t
        )
    )

    ns = "aws:autoscaling:asg"
    # Bounds come from the live catalog so the check tracks AWS limit changes.
    catalog = eb.describe_configuration_options(SolutionStackName=stack)["Options"]
    max_size = _described(catalog, ns, "MaxSize")
    assert max_size.get("ValueType") == "Scalar", (
        f"{ns}/MaxSize must be described as a Scalar option, got {max_size.get('ValueType')!r}"
    )
    assert "MinValue" in max_size and "MaxValue" in max_size, (
        f"a ranged Scalar option must publish both MinValue and MaxValue, got {max_size!r}"
    )
    lo, hi = int(max_size["MinValue"]), int(max_size["MaxValue"])
    assert lo < hi, f"{ns}/MaxSize MinValue must be below MaxValue, got {lo} and {hi}"

    # --- Control, established BEFORE the negative: both published boundaries are legal. ---
    for boundary in (hi, max(lo, 1)):
        control = eb.validate_configuration_settings(
            ApplicationName=app_name,
            TemplateName=template_name,
            OptionSettings=[{"Namespace": ns, "OptionName": "MaxSize", "Value": str(boundary)}],
        )["Messages"]
        assert _errors_for(control, ns, "MaxSize") == [], (
            f"MaxSize={boundary} is inside the published range [{lo}, {hi}] and must produce no "
            f"error-severity ValidationMessage, got {control!r}"
        )

    # --- Break exactly one thing: one past the published maximum. ---
    over = {"Namespace": ns, "OptionName": "MaxSize", "Value": str(hi + 1)}
    messages = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=[over]
    )["Messages"]
    scoped = _errors_for(messages, ns, "MaxSize")
    assert len(scoped) == 1, (
        f"MaxSize={hi + 1} is one past the published MaxValue {hi} and must produce exactly one "
        f"error-severity ValidationMessage on ({ns!r}, 'MaxSize'); got {messages!r}"
    )
    assert scoped[0]["Namespace"] == ns and scoped[0]["OptionName"] == "MaxSize", scoped[0]
    expected_validation_message = (
        f"Invalid option value: '{hi + 1}' (Namespace: '{ns}', OptionName: 'MaxSize'): "
        f"Value exceeds maximum allowed value: {hi}"
    )
    assert scoped[0]["Message"] == expected_validation_message, (
        f"expected the exact ValidationMessage text {expected_validation_message!r}, got {scoped[0]["Message"]!r}"
    )

    # --- Effect absent: the write carrying the out-of-range value is refused, value unchanged. ---
    eb.update_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[{"Namespace": ns, "OptionName": "MaxSize", "Value": str(hi)}],
    )
    code, message = _err(
        lambda: eb.update_configuration_template(
            ApplicationName=app_name, TemplateName=template_name, OptionSettings=[over]
        )
    )
    # ConfigurationValidationException (HTTP 400) is not a modeled error of
    # UpdateConfigurationTemplate; its message prefixes the ValidationMessage text.
    assert code == "ConfigurationValidationException", (
        f"UpdateConfigurationTemplate with MaxSize={hi + 1} (past the published MaxValue {hi}) must "
        f"be refused with ConfigurationValidationException, got {code!r}"
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
        if o.get("Namespace") == ns and o.get("OptionName") == "MaxSize"
    ]
    assert len(stored) == 1 and stored[0]["Value"] == str(hi), (
        f"the refused update must leave the previously stored MaxSize={hi} intact, got {stored!r}"
    )

    # --- Control still works after the refusal. ---
    legal = max(lo, 1) + 1
    eb.update_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[{"Namespace": ns, "OptionName": "MaxSize", "Value": str(legal)}],
    )
    after = [
        o
        for o in eb.describe_configuration_settings(
            ApplicationName=app_name, TemplateName=template_name
        )["ConfigurationSettings"][0]["OptionSettings"]
        if o.get("Namespace") == ns and o.get("OptionName") == "MaxSize"
    ]
    assert len(after) == 1 and after[0]["Value"] == str(legal), (
        f"after a refused update the template must still accept an in-range MaxSize, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
