"""start-session-nonexistent-application-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-session-nonexistent-application-not-found"
GROUP = "error-semantics"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": "start-session-nonexistent-application-not-found"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartConfigurationSession against a nonexistent application is rejected as ResourceNotFoundException."""
    # positive control: a real, deployed application/environment/profile works
    app_id, env_id, profile_id = _setup_deployed_profile(ctx, content=b'{"ok":true}', content_type="application/json")

    appconfigdata = ctx.client("appconfigdata")
    control_token = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
    )["InitialConfigurationToken"]
    assert control_token, (
        "positive control: start_configuration_session against the real deployed "
        "application/environment/profile returned no InitialConfigurationToken"
    )

    code, message = _client_error(
        lambda: appconfigdata.start_configuration_session(
            ApplicationIdentifier="zzzzzzz",
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=profile_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"start_configuration_session against a nonexistent ApplicationIdentifier must be "
        f"rejected ResourceNotFoundException, got {code!r}"
    )
    assert message == "Application not found", f"expected message 'Application not found', got {message!r}"


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


def _ignore_not_found(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if code != "ResourceNotFoundException":
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-acd-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-acd-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    )
    return env_id


def _create_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-acd-profile-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
        )
    )
    return profile_id


def _create_hosted_version(ctx, app_id, profile_id, content, content_type="application/json", version_label=None):
    appconfig = ctx.client("appconfig")
    kwargs = dict(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )
    if version_label:
        kwargs["VersionLabel"] = version_label
    version_number = appconfig.create_hosted_configuration_version(**kwargs)["VersionNumber"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
            )
        )
    )
    return version_number


def _deploy_version(ctx, app_id, env_id, profile_id, version_number, timeout_s=150.0):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-acd-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    )
    resp = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = resp["DeploymentNumber"]
    state = resp.get("State")
    deadline = time.monotonic() + timeout_s
    while state != "COMPLETE" and time.monotonic() < deadline:
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state {state}")
        time.sleep(3)
        state = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"]
    if state != "COMPLETE":
        raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s, last state={state}")
    return deployment_number


def _setup_deployed_profile(ctx, content=b'{"flag":true}', content_type="application/json", version_label=None):
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)
    version_number = _create_hosted_version(ctx, app_id, profile_id, content, content_type, version_label)
    _deploy_version(ctx, app_id, env_id, profile_id, version_number)
    return app_id, env_id, profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
