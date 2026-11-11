"""profile-deployed-to-one-environment-not-another-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "profile-deployed-to-one-environment-not-another-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A profile that has been deployed to one environment of an application has no
    deployed configuration for a DIFFERENT, sibling environment of that same
    application: starting a session against the un-deployed pairing is rejected."""
    app_id = _create_application(ctx)
    profile_id = _create_profile(ctx, app_id)
    deployed_env = _create_environment(ctx, app_id)
    bare_env = _create_environment(ctx, app_id)

    content = b'{"deployed":"to-one-env-only"}'
    version_number = _create_hosted_version(ctx, app_id, profile_id, content)
    _deploy_version(ctx, app_id, deployed_env, profile_id, version_number)

    appconfigdata = ctx.client("appconfigdata")

    # break exactly one thing: request a session for the SAME profile against the
    # sibling environment that never received a deployment
    code, message = _client_error(
        lambda: appconfigdata.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=bare_env,
            ConfigurationProfileIdentifier=profile_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"starting a session against the un-deployed sibling environment {bare_env!r} "
        f"should be rejected ResourceNotFoundException, got {code!r}"
    )
    assert message == "Deployment not found", f"expected message 'Deployment not found', got {message!r}"

    # positive control: the environment that actually received the deployment works
    control = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=deployed_env,
        ConfigurationProfileIdentifier=profile_id,
    )
    resp = appconfigdata.get_latest_configuration(ConfigurationToken=control["InitialConfigurationToken"])
    served = resp["Configuration"].read()
    assert served == content, (
        f"the deployed environment {deployed_env!r} should serve {content!r}, got {served!r} -- "
        "if this fails the setup was broken and the rejection above proves nothing"
    )


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


def _create_hosted_version(ctx, app_id, profile_id, content, content_type="application/json"):
    appconfig = ctx.client("appconfig")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]
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
        Tags=_TAGS,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
