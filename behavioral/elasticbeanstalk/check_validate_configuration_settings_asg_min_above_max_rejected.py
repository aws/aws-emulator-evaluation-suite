"""validate-configuration-settings-asg-min-above-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "validate-configuration-settings-asg-min-above-max-rejected"
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


def _asg(namespace, option_name, value):
    return {"Namespace": namespace, "OptionName": option_name, "Value": str(value)}


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MinSize > MaxSize, each individually in range, yields error ValidationMessages on both and a
    refused UpdateConfigurationTemplate that leaves the stored legal pair intact."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    ns = "aws:autoscaling:asg"
    stack = _solution_stack(eb)
    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        OptionSettings=[_asg(ns, "MinSize", 2), _asg(ns, "MaxSize", 4)],
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(
        lambda _a=app_name, _t=template_name: eb.delete_configuration_template(
            ApplicationName=_a, TemplateName=_t
        )
    )

    legal = [_asg(ns, "MinSize", 2), _asg(ns, "MaxSize", 4)]
    inverted = [_asg(ns, "MinSize", 4), _asg(ns, "MaxSize", 2)]

    # --- Each half of the inverted pair is individually inside its published range. ---
    catalog = eb.describe_configuration_options(SolutionStackName=stack)["Options"]
    for option_name, value in (("MinSize", 4), ("MaxSize", 2)):
        desc = [o for o in catalog if o.get("Namespace") == ns and o.get("Name") == option_name]
        assert len(desc) == 1, f"{ns}/{option_name} must be described exactly once, got {desc!r}"
        lo, hi = int(desc[0]["MinValue"]), int(desc[0]["MaxValue"])
        assert lo <= value <= hi, (
            f"the co-requirement test requires {option_name}={value} to be individually legal; "
            f"published range is [{lo}, {hi}]"
        )

    # --- Control, established BEFORE the negative: the legal orientation validates clean. ---
    control = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=legal
    )["Messages"]
    control_errors = [m for m in control if m.get("Severity") == "error"]
    assert control_errors == [], (
        f"MinSize=2 with MaxSize=4 is a legal pair and must produce no error-severity "
        f"ValidationMessage, got {control_errors!r}"
    )

    # --- Break exactly one thing: invert the pair. ---
    messages = eb.validate_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name, OptionSettings=inverted
    )["Messages"]
    errors = [m for m in messages if m.get("Severity") == "error"]
    assert errors, (
        f"MinSize=4 with MaxSize=2 violates the documented MinSize<=MaxSize co-requirement and must "
        f"produce at least one error-severity ValidationMessage; got {messages!r}"
    )
    scoped = [m for m in errors if m.get("Namespace") == ns]
    assert scoped, (
        f"the co-requirement violation must be attributed to the {ns!r} namespace, got {errors!r}"
    )
    assert {m.get("OptionName") for m in scoped} <= {"MinSize", "MaxSize"}, (
        f"the co-requirement violation must be attributed to MinSize and/or MaxSize, got "
        f"{[m.get('OptionName') for m in scoped]!r}"
    )
    min_size_message = (
        f"Invalid option value: '4' (Namespace: '{ns}', OptionName: 'MinSize'): "
        f"MinSize is greater than MaxSize"
    )
    max_size_message = (
        f"Invalid option value: '2' (Namespace: '{ns}', OptionName: 'MaxSize'): "
        f"MaxSize is less than MinSize"
    )
    scoped_messages = {m.get("OptionName"): m.get("Message") for m in scoped}
    assert scoped_messages == {"MinSize": min_size_message, "MaxSize": max_size_message}, (
        f"expected the exact ValidationMessage text on both halves of the inverted pair, "
        f"got {scoped_messages!r}"
    )

    # --- Effect absent: the write is refused and the stored legal pair is untouched. ---
    code, message = _err(
        lambda: eb.update_configuration_template(
            ApplicationName=app_name, TemplateName=template_name, OptionSettings=inverted
        )
    )
    # ConfigurationValidationException (HTTP 400) is not a modeled error of
    # UpdateConfigurationTemplate; its message prefixes the ValidationMessage text.
    assert code == "ConfigurationValidationException", (
        f"UpdateConfigurationTemplate with MinSize=4/MaxSize=2 must be refused with "
        f"ConfigurationValidationException, got {code!r}"
    )
    # message varies: the refusal carries exactly one of the two ValidationMessage texts above, and
    # real AWS picks the MinSize or the MaxSize half from run to run; both exact forms are allowed.
    allowed = {
        f"Configuration validation exception: {min_size_message}",
        f"Configuration validation exception: {max_size_message}",
    }
    assert message in allowed, f"expected one of {sorted(allowed)!r}, got {message!r}"
    stored = {
        o["OptionName"]: o["Value"]
        for o in eb.describe_configuration_settings(
            ApplicationName=app_name, TemplateName=template_name
        )["ConfigurationSettings"][0]["OptionSettings"]
        if o.get("Namespace") == ns and o.get("OptionName") in ("MinSize", "MaxSize")
    }
    assert stored == {"MinSize": "2", "MaxSize": "4"}, (
        f"the refused update must leave the stored legal pair intact, got {stored!r}"
    )

    # --- Control still works after the refusal. ---
    eb.update_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[_asg(ns, "MinSize", 3), _asg(ns, "MaxSize", 5)],
    )
    after = {
        o["OptionName"]: o["Value"]
        for o in eb.describe_configuration_settings(
            ApplicationName=app_name, TemplateName=template_name
        )["ConfigurationSettings"][0]["OptionSettings"]
        if o.get("Namespace") == ns and o.get("OptionName") in ("MinSize", "MaxSize")
    }
    assert after == {"MinSize": "3", "MaxSize": "5"}, (
        f"after a refused update the template must still accept a legal pair, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
