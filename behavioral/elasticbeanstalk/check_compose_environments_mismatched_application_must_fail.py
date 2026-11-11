"""compose-environments-mismatched-application-must-fail."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compose-environments-mismatched-application-must-fail"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ComposeEnvironments with another application's version label fails with MissingParameter "No valid
    application version found." and creates no environment, while the application's own unprocessed version
    fails with ConfigurationValidationException and its exact message."""
    eb = ctx.client("elasticbeanstalk")

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    app_a = ctx.unique_name("sim2real-eb-appa-")
    app_b = ctx.unique_name("sim2real-eb-appb-")
    eb.create_application(ApplicationName=app_a, Tags=resource_tags)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_a, TerminateEnvByForce=False))
    eb.create_application(ApplicationName=app_b, Tags=resource_tags)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_b, TerminateEnvByForce=False))

    # Omitting SourceBundle/SourceBuildInformation makes CreateApplicationVersion use the
    # built-in sample application bundle -- cheap, and application-membership is all that
    # matters for this check (ComposeEnvironments must not compose it either way).
    version_b = ctx.unique_name("v-")
    eb.create_application_version(ApplicationName=app_b, VersionLabel=version_b, Tags=resource_tags)
    version_a = ctx.unique_name("v-")
    eb.create_application_version(ApplicationName=app_a, VersionLabel=version_a, Tags=resource_tags)

    # Break exactly one thing: reference app_b's version label while composing against app_a.
    code, message = _error_code(
        lambda: eb.compose_environments(ApplicationName=app_a, VersionLabels=[version_b])
    )
    # Filtering VersionLabels to those of ApplicationName leaves none, which the service reports as
    # MissingParameter: the call is refused, not composed against the wrong application.
    assert code == "MissingParameter", f"unexpected error code: {code}"
    expected = "No valid application version found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no environment was created under app_a as a result of the rejected call.
    envs = eb.describe_environments(ApplicationName=app_a, IncludeDeleted=False)["Environments"]
    assert envs == [], f"an environment was unexpectedly created under {app_a}: {envs}"

    # Contrast control: app_a's own unprocessed version fails differently (ConfigurationValidationException),
    # so the MissingParameter above is about cross-application scoping.
    code2, message2 = _error_code(
        lambda: eb.compose_environments(ApplicationName=app_a, VersionLabels=[version_a])
    )
    assert code2 == "ConfigurationValidationException", f"unexpected error code: {code2}"
    expected2 = f"ApplicationVersion {version_a} has not been successfully processed. Current status: UNPROCESSED"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # And still no environment materialized under app_a from either rejected call.
    envs = eb.describe_environments(ApplicationName=app_a, IncludeDeleted=False)["Environments"]
    assert envs == [], f"an environment was unexpectedly created under {app_a}: {envs}"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected ComposeEnvironments to raise a ClientError, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
