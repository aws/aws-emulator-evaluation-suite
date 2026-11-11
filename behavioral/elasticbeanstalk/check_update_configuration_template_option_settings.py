"""update-configuration-template-option-settings."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "update-configuration-template-option-settings"
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
    """UpdateConfigurationTemplate overwrites an option's value on the stored template."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "fidelity-key", "Value": "fidelity-value"}],
    )
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
                "Value": "original",
            }
        ],
        Tags=[{"Key": "fidelity-key", "Value": "fidelity-value"}],
    )
    ctx.on_cleanup(lambda _a=app_name, _t=template_name: eb.delete_configuration_template(ApplicationName=_a, TemplateName=_t))

    eb.update_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[
            {
                "Namespace": "aws:elasticbeanstalk:application:environment",
                "OptionName": "FIDELITY_TEST_VAR",
                "Value": "updated",
            }
        ],
    )

    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )
    options = settings["ConfigurationSettings"][0]["OptionSettings"]
    matching = [o for o in options if o["OptionName"] == "FIDELITY_TEST_VAR"]
    assert len(matching) == 1, (
        f"expected exactly one FIDELITY_TEST_VAR option after UpdateConfigurationTemplate, "
        f"got {matching!r}"
    )
    assert matching[0]["Value"] == "updated", (
        f"expected FIDELITY_TEST_VAR to resolve to 'updated' after UpdateConfigurationTemplate, "
        f"got {matching[0]['Value']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
