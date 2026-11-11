"""create-configuration-template-unknown-application-must-fail."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-template-unknown-application-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_STACK_CACHE = []

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationTemplate for an application that does not exist must be rejected,
    and the identical call must succeed once that application is created."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-absent-")
    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    stack = _solution_stack(eb)

    code, message = _err(
        lambda: eb.create_configuration_template(
            ApplicationName=app_name,
            TemplateName=template_name,
            SolutionStackName=stack,
        )
    )
    assert code == "InvalidParameterValue", (
        f"CreateConfigurationTemplate for an unknown application must fail with "
        f"InvalidParameterValue, got {code!r}"
    )
    expected = f"No Application named '{app_name}' found."
    assert message == expected, (
        f"CreateConfigurationTemplate for an unknown application must say {expected!r}, "
        f"got {message!r}"
    )

    listed = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert listed == [], "a rejected template creation must not auto-create the application"

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
    )
    ctx.on_cleanup(
        lambda _a=app_name, _t=template_name: eb.delete_configuration_template(
            ApplicationName=_a, TemplateName=_t
        )
    )

    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"]
    assert len(settings) == 1 and settings[0]["TemplateName"] == template_name, (
        "the identical CreateConfigurationTemplate call must succeed once the application "
        f"exists, got {settings!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
