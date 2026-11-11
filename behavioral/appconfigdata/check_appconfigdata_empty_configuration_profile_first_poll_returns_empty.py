"""appconfigdata-empty-configuration-profile-first-poll-returns-empty."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-empty-configuration-profile-first-poll-returns-empty"
GROUP = "state"
SERVICES = ["appconfigdata"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartConfigurationSession on a never-deployed profile is refused ResourceNotFoundException
    "Deployment not found" (not an empty first poll), while a deployed sibling opens a session and
    the same profile serves its content once deployed."""
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)
    strategy_id = _create_strategy(ctx)

    appconfig = ctx.client("appconfig")
    appconfigdata = ctx.client("appconfigdata")

    control_profile_id = _create_profile(ctx, app_id)
    control_version = _create_hosted_version(ctx, app_id, control_profile_id, b'{"control":true}')
    _deploy_and_wait(ctx, app_id, env_id, control_profile_id, strategy_id, control_version)
    control_token = _start_session_once_deployed(
        appconfigdata, app_id, env_id, control_profile_id
    )["InitialConfigurationToken"]
    assert control_token, "positive control: expected a session token from a deployed sibling profile"

    deployments = appconfig.list_deployments(ApplicationId=app_id, EnvironmentId=env_id).get("Items", [])
    assert not any(d.get("ConfigurationProfileId") == profile_id for d in deployments), (
        f"expected no deployment recorded yet for the untested profile, got {deployments}"
    )

    code, message = _client_error(
        lambda: appconfigdata.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=profile_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Deployment not found", f"expected message 'Deployment not found', got {message!r}"

    restored_content = b'{"restored":true}'
    version_number = _create_hosted_version(ctx, app_id, profile_id, restored_content)
    _deploy_and_wait(ctx, app_id, env_id, profile_id, strategy_id, version_number)

    session = _start_session_once_deployed(appconfigdata, app_id, env_id, profile_id)
    resp = appconfigdata.get_latest_configuration(
        ConfigurationToken=session["InitialConfigurationToken"]
    )
    body = resp["Configuration"].read()
    assert body == restored_content, f"expected {restored_content!r} after restore, got {body!r}"


def _client_error(fn):
    """Return (code, message) for a call that must be refused.

    Raises AssertionError when the call succeeds: an emulator that accepts what AWS refuses
    must fail loudly, not read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


def _start_session_once_deployed(appconfigdata, app_id, env_id, profile_id, timeout_s=30.0):
    """Start a session, retrying the brief "Deployment not found" gap right after COMPLETE."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appconfigdata.start_configuration_session(
                ApplicationIdentifier=app_id,
                EnvironmentIdentifier=env_id,
                ConfigurationProfileIdentifier=profile_id,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"StartConfigurationSession still ResourceNotFoundException {timeout_s}s "
                    "after the deployment reached COMPLETE"
                ) from exc
            time.sleep(2.0)


def _create_hosted_version(ctx, app_id, profile_id, content, content_type="application/json"):
    appconfig = ctx.client("appconfig")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]

    def _cleanup():
        try:
            appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return version_number


def _create_strategy(ctx):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return strategy_id


def _deploy_and_wait(ctx, app_id, env_id, profile_id, strategy_id, version_number, timeout_s=120.0):
    appconfig = ctx.client("appconfig")
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"]
        if state == "COMPLETE":
            return deployment_number
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered unexpected state {state}")
        time.sleep(3)
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s, last state={state}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]

    def _cleanup():
        try:
            appconfig.delete_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-")
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return env_id


def _create_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
