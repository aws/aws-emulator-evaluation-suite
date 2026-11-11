"""environment-deletion-does-not-immediately-break-active-session-or-new-session."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-deletion-does-not-immediately-break-active-session-or-new-session"
GROUP = "state"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting the ENVIRONMENT underlying an active session does not retroactively
    invalidate that session's already-active data-plane token. An unrelated session on a
    different, undeleted environment is unaffected throughout."""
    control_app, control_env, control_profile, _control_version = _setup_deployed_profile(
        ctx, content=b'{"control":true}', content_type="application/json"
    )
    victim_app, victim_env, victim_profile, _victim_version = _setup_deployed_profile(
        ctx, content=b'{"victim":true}', content_type="application/json"
    )

    appconfigdata = ctx.client("appconfigdata")

    control_token = appconfigdata.start_configuration_session(
        ApplicationIdentifier=control_app,
        EnvironmentIdentifier=control_env,
        ConfigurationProfileIdentifier=control_profile,
    )["InitialConfigurationToken"]
    victim_token = appconfigdata.start_configuration_session(
        ApplicationIdentifier=victim_app,
        EnvironmentIdentifier=victim_env,
        ConfigurationProfileIdentifier=victim_profile,
    )["InitialConfigurationToken"]

    control_first = appconfigdata.get_latest_configuration(ConfigurationToken=control_token)
    assert control_first["Configuration"].read() == b'{"control":true}', (
        f"expected control's first poll to carry the deployed control content, "
        f"got {control_first['Configuration'].read()!r}"
    )
    control_next_token = control_first["NextPollConfigurationToken"]

    victim_first = appconfigdata.get_latest_configuration(ConfigurationToken=victim_token)
    assert victim_first["Configuration"].read() == b'{"victim":true}', (
        f"expected victim's first poll to carry the deployed victim content, "
        f"got {victim_first['Configuration'].read()!r}"
    )
    victim_next_token = victim_first["NextPollConfigurationToken"]

    # break exactly one thing: delete the victim's environment
    appconfig = ctx.client("appconfig")
    appconfig.delete_environment(ApplicationId=victim_app, EnvironmentId=victim_env)

    # the already-active session's data-plane token keeps working: same no-change
    # semantics as the untouched control (empty body, since nothing redeployed),
    # not merely a response that happens to carry the expected field.
    victim_second = appconfigdata.get_latest_configuration(ConfigurationToken=victim_next_token)
    assert victim_second["Configuration"].read() == b"", (
        f"expected victim's post-deletion poll to report no change (empty body) "
        f"like an unaffected session, got {victim_second['Configuration'].read()!r}"
    )
    assert "NextPollConfigurationToken" in victim_second, (
        "expected a NextPollConfigurationToken on the post-deletion poll, "
        f"got keys {sorted(victim_second.keys())}"
    )

    # positive control: the unrelated session is unaffected
    control_second = appconfigdata.get_latest_configuration(ConfigurationToken=control_next_token)
    assert control_second["Configuration"].read() == b"", (
        f"expected the unrelated control session's second poll to report no change "
        f"(empty body), got {control_second['Configuration'].read()!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


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


def _setup_deployed_profile(ctx, content=b'{"flag":true}', content_type="application/json"):
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)
    version_number = _create_hosted_version(ctx, app_id, profile_id, content, content_type)
    _deploy_version(ctx, app_id, env_id, profile_id, version_number)
    return app_id, env_id, profile_id, version_number


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
