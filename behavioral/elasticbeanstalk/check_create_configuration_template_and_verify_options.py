"""create-configuration-template-and-verify-options."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-configuration-template-and-verify-options"
GROUP = 'configuration-templates'
SERVICES = ['elasticbeanstalk']

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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationTemplate persists the FIDELITY_TEST_VAR option, and DescribeConfigurationSettings
    returns it with its value among the full resolved option set (platform defaults included), not only the
    option written."""
    eb = ctx.client("elasticbeanstalk")
    tag = [{"Key": "sim2real", "Value": "true"}]
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=_solution_stack(eb),
        OptionSettings=[
            {
                "Namespace": "aws:elasticbeanstalk:application:environment",
                "OptionName": "FIDELITY_TEST_VAR",
                "Value": "abc123",
            }
        ],
        Tags=tag,
    )
    ctx.on_cleanup(lambda _a=app_name, _t=template_name: eb.delete_configuration_template(ApplicationName=_a, TemplateName=_t))

    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )
    options = settings["ConfigurationSettings"][0]["OptionSettings"]
    matching = [
        o
        for o in options
        if o["Namespace"] == "aws:elasticbeanstalk:application:environment"
        and o["OptionName"] == "FIDELITY_TEST_VAR"
    ]
    assert len(matching) == 1, f"expected exactly one FIDELITY_TEST_VAR option, got {matching!r}"
    assert matching[0]["Value"] == "abc123", (
        f"expected FIDELITY_TEST_VAR Value 'abc123', got {matching[0]['Value']!r}"
    )
    assert len(options) > 1, (
        f"DescribeConfigurationSettings must return the full RESOLVED option set (platform "
        f"defaults plus the one override this check wrote), not just the written option — an "
        f"echo-only emulator would otherwise pass; got {len(options)} option(s): {options!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
