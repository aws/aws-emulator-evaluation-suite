"""sibling-environment-deployment-does-not-leak-into-active-session."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sibling-environment-deployment-does-not-leak-into-active-session"
GROUP = "state"
SERVICES = ["appconfigdata"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A new deployment of the same profile to a SIBLING environment must not be
    visible to an already-active session bound to a different environment."""
    app_id = _create_application(ctx)
    profile_id = _create_profile(ctx, app_id)
    env_1 = _create_environment(ctx, app_id)
    env_2 = _create_environment(ctx, app_id)

    content_1 = b'{"env":"one"}'
    version_1 = _create_hosted_version(ctx, app_id, profile_id, content_1)
    _deploy_version(ctx, app_id, env_1, profile_id, version_1)

    appconfigdata = ctx.client("appconfigdata")
    token_1 = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_1,
        ConfigurationProfileIdentifier=profile_id,
    )["InitialConfigurationToken"]
    first_1 = appconfigdata.get_latest_configuration(ConfigurationToken=token_1)
    body_1 = first_1["Configuration"].read()
    assert body_1 == content_1, f"expected env_1 initial read {content_1!r}, got {body_1!r}"
    next_token_1 = first_1["NextPollConfigurationToken"]

    # break exactly one thing: deploy new content to the SIBLING environment (env_2)
    content_2 = b'{"env":"two"}'
    version_2 = _create_hosted_version(ctx, app_id, profile_id, content_2)
    _deploy_version(ctx, app_id, env_2, profile_id, version_2)

    # env_1's active session must see "no change" -- never env_2's content
    second_1 = appconfigdata.get_latest_configuration(ConfigurationToken=next_token_1)
    body_2 = second_1["Configuration"].read()
    assert body_2 == b"", f"expected env_1 session to see no change (b''), got {body_2!r} (env_2 leaked)"

    # positive control: env_2's own session sees its own deployed content
    token_2 = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_2,
        ConfigurationProfileIdentifier=profile_id,
    )["InitialConfigurationToken"]
    first_2 = appconfigdata.get_latest_configuration(ConfigurationToken=token_2)
    body_3 = first_2["Configuration"].read()
    assert body_3 == content_2, f"expected env_2's own session to see {content_2!r}, got {body_3!r}"


def _ignore_not_found(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if code != "ResourceNotFoundException":
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-acd-app-"))["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-acd-env-"))["Id"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
