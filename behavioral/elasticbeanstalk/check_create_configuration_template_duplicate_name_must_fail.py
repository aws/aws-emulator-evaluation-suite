"""create-configuration-template-duplicate-name-must-fail."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-template-duplicate-name-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected success raises, so an
    emulator accepting a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
    """CreateConfigurationTemplate on an existing template name must be rejected, not an upsert."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    original = eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=_solution_stack(eb),
        Description="sim2real original",
    )
    ctx.on_cleanup(lambda _a=app_name, _t=template_name: eb.delete_configuration_template(ApplicationName=_a, TemplateName=_t))
    assert original["Description"] == "sim2real original", original

    # The duplicate carries a DIFFERENT Description, so an upsert-as-clobber is observable
    # rather than merely suspected.
    code, message = _err(
        lambda: eb.create_configuration_template(
            ApplicationName=app_name,
            TemplateName=template_name,
            SolutionStackName=_solution_stack(eb),
            Description="sim2real clobbered",
        )
    )
    assert code == "InvalidParameterValue", (
        f"duplicate CreateConfigurationTemplate must fail with InvalidParameterValue, "
        f"got {code!r}"
    )
    expected = f"Configuration Template {template_name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent (no clobber): an independent read shows the original template untouched.
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"]
    assert len(settings) == 1, settings
    assert settings[0]["Description"] == "sim2real original", (
        f"the rejected duplicate clobbered the template's Description: "
        f"{settings[0]['Description']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
