"""create-environment-invalid-solution-stack-must-fail."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-environment-invalid-solution-stack-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment with a nonexistent SolutionStackName must be rejected, not silently
    accepted -- proven against a positive control showing the same application accepts a valid
    stack for a configuration template, so the rejection is specific to the bogus name."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)

    # Positive control on the same parameter: a configuration template on the same application
    # accepts the valid SolutionStackName, so a later rejection cannot be "every stack name fails".
    template = ctx.unique_name("sim2real-behav-eb-tpl-")
    created = eb.create_configuration_template(
        ApplicationName=app_name, TemplateName=template, SolutionStackName=stack
    )
    ctx.on_cleanup(lambda: _delete_template(eb, app_name, template))
    assert created["TemplateName"] == template and created["SolutionStackName"] == stack, (
        f"positive control: CreateConfigurationTemplate with a real SolutionStackName must be "
        f"accepted with that stack, got {created!r}"
    )

    # Negative: an always-invalid SolutionStackName (this exact string can never become valid,
    # so there is no restore leg here) must be rejected with the specific error.
    bad_env = ctx.unique_name("sim2real-behav-eb-env-bad-")
    bogus_stack = "64bit Definitely/Not A Real Solution Stack v0.0.0"
    code, status, message = _error_code(
        lambda: eb.create_environment(
            ApplicationName=app_name,
            EnvironmentName=bad_env,
            SolutionStackName=bogus_stack,
        )
    )
    assert code == "InvalidParameterValue", (
        f"creating an environment with a bogus SolutionStackName must fail with "
        f"InvalidParameterValue, got {code!r}"
    )
    assert status == 400, f"the bogus SolutionStackName refusal must be HTTP 400, got {status}"
    expected_message = f"No Solution Stack named '{bogus_stack}' found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent, at an independent read: the rejected call created no environment.
    bad_envs = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[bad_env], IncludeDeleted=False
    )["Environments"]
    live_bad = [e for e in bad_envs if e["Status"] != "Terminated"]
    assert not live_bad, (
        f"the rejected CreateEnvironment must not create an environment, found {live_bad!r}"
    )

    # The positive control's template is untouched and still carries the valid stack.
    settings = eb.describe_configuration_settings(ApplicationName=app_name, TemplateName=template)[
        "ConfigurationSettings"
    ]
    assert [s_.get("SolutionStackName") for s_ in settings] == [stack], (
        f"the positive control's template must remain on {stack!r}, got {settings!r}"
    )

    # The template is deleted and gone: unreadable, unlisted, and refused for update.
    eb.delete_configuration_template(ApplicationName=app_name, TemplateName=template)
    code, status, message = _error_code(
        lambda: eb.describe_configuration_settings(ApplicationName=app_name, TemplateName=template)
    )
    assert (code, status) == ("InvalidParameterValue", 400), (
        f"expected InvalidParameterValue/400 reading the deleted template, got {code!r}/{status}"
    )
    expected_message = f"No Configuration Template named '{app_name}/{template}' found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    listed = [t for a in apps for t in a.get("ConfigurationTemplates", [])]
    assert template not in listed, f"expected {template!r} absent from the application's templates, got {listed!r}"
    code, status, message = _error_code(
        lambda: eb.update_configuration_template(
            ApplicationName=app_name, TemplateName=template, Description=CHECK
        )
    )
    assert (code, status) == ("InvalidParameterValue", 400), (
        f"expected InvalidParameterValue/400 updating the deleted template, got {code!r}/{status}"
    )
    expected_message = f"No Configuration Template named '{app_name}/{template}' found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, int, str]:
    """Call fn(); return (Error.Code, HTTP status, Error.Message) of the ClientError it raises.
    An unexpected success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response["ResponseMetadata"]["HTTPStatusCode"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_template(eb, app_name, template):
    """Teardown: delete the template, tolerating only the not-found answer for one already gone."""
    try:
        eb.delete_configuration_template(ApplicationName=app_name, TemplateName=template)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidParameterValue":
            raise


def _pick_solution_stack(eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux" in s and "running" in s and "Docker" not in s:
            return s
    return stacks[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
