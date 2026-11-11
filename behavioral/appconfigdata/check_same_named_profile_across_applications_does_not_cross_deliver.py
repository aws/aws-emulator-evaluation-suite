"""same-named-profile-across-applications-does-not-cross-deliver."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "same-named-profile-across-applications-does-not-cross-deliver"
GROUP = "state"
SERVICES = ["appconfigdata"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two applications with same-named profiles deployed with different content do not
    cross-deliver: a session started by profile name under each serves only its own content."""
    shared_profile_name = ctx.unique_name("sim2real-acd-shared-profile-")

    app_a, env_a, content_a = _setup_named_profile(ctx, shared_profile_name, b'{"tenant":"a"}')
    app_b, env_b, content_b = _setup_named_profile(ctx, shared_profile_name, b'{"tenant":"b"}')

    appconfigdata = ctx.client("appconfigdata")

    token_a = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_a,
        EnvironmentIdentifier=env_a,
        ConfigurationProfileIdentifier=shared_profile_name,
    )["InitialConfigurationToken"]
    resp_a = appconfigdata.get_latest_configuration(ConfigurationToken=token_a)
    body_a = resp_a["Configuration"].read()
    assert body_a == content_a, (
        f"session started under application A (name {shared_profile_name!r}) served {body_a!r}, "
        f"expected A's own deployed content {content_a!r} -- possible cross-application delivery"
    )

    token_b = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_b,
        EnvironmentIdentifier=env_b,
        ConfigurationProfileIdentifier=shared_profile_name,
    )["InitialConfigurationToken"]
    resp_b = appconfigdata.get_latest_configuration(ConfigurationToken=token_b)
    body_b = resp_b["Configuration"].read()
    assert body_b == content_b, (
        f"session started under application B (name {shared_profile_name!r}) served {body_b!r}, "
        f"expected B's own deployed content {content_b!r} -- possible cross-application delivery"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if code != "ResourceNotFoundException":
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-acd-app-"), Tags={"sim2real-check": CHECK}
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-acd-env-"), Tags={"sim2real-check": CHECK}
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    )
    return env_id


def _create_named_profile(ctx, app_id, name):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=name,
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags={"sim2real-check": CHECK},
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
        Tags={"sim2real-check": CHECK},
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


def _setup_named_profile(ctx, profile_name, content):
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_named_profile(ctx, app_id, profile_name)
    version_number = _create_hosted_version(ctx, app_id, profile_id, content)
    _deploy_version(ctx, app_id, env_id, profile_id, version_number)
    return app_id, env_id, content


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
