"""delete-configuration-template-removes-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-configuration-template-removes-it"
GROUP = 'configuration-templates'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised, else raise."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError against the deleted template, but the call succeeded")


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
    """After DeleteConfigurationTemplate: an independent read no longer finds the template with
    a specific not-found code, a mutation against the dead id fails the same way, and the freed
    name is reusable."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    stack = _solution_stack(eb)
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
    )

    before = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"]
    assert len(before) == 1 and before[0]["TemplateName"] == template_name, (
        f"expected the freshly created template to describe cleanly before delete, got {before!r}"
    )

    eb.delete_configuration_template(ApplicationName=app_name, TemplateName=template_name)

    code, message = _err(
        lambda: eb.describe_configuration_settings(
            ApplicationName=app_name, TemplateName=template_name
        )
    )
    assert code == "InvalidParameterValue", (
        f"describing a deleted configuration template must fail with InvalidParameterValue, "
        f"got {code!r}"
    )
    expected = f"No Configuration Template named '{app_name}/{template_name}' found."
    assert message == expected, (
        f"describing a deleted configuration template must say {expected!r}, got {message!r}"
    )

    mutate_code, mutate_message = _err(
        lambda: eb.update_configuration_template(
            ApplicationName=app_name,
            TemplateName=template_name,
            OptionSettings=[{
                "Namespace": "aws:autoscaling:launchconfiguration",
                "OptionName": "InstanceType",
                "Value": "t3.small",
            }],
        )
    )
    assert mutate_code == "InvalidParameterValue", (
        f"UpdateConfigurationTemplate against a deleted template must fail with "
        f"InvalidParameterValue, got {mutate_code!r}"
    )
    mutate_expected = f"No Configuration Template named '{app_name}/{template_name}' found."
    assert mutate_message == mutate_expected, (
        f"UpdateConfigurationTemplate against a deleted template must say "
        f"{mutate_expected!r}, got {mutate_message!r}"
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

    after = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"]
    assert len(after) == 1 and after[0]["TemplateName"] == template_name, (
        f"the freed template name must be reusable once recreated, got {after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
