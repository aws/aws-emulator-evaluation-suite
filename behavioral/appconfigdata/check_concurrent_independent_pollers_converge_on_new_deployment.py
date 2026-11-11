"""concurrent-independent-pollers-converge-on-new-deployment."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-independent-pollers-converge-on-new-deployment"
GROUP = "concurrency"
SERVICES = ["appconfigdata"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a completed deployment, N independently-started sessions polling in
    parallel each converge on the SAME new content -- concurrent pollers never see a
    mix of stale and fresh data once the deployment has reached COMPLETE."""
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)

    v1_content = b'{"v":1}'
    v1 = _create_hosted_version(ctx, app_id, profile_id, v1_content)
    _deploy_version(ctx, app_id, env_id, profile_id, v1)

    v2_content = b'{"v":2}'
    v2 = _create_hosted_version(ctx, app_id, profile_id, v2_content)
    _deploy_version(ctx, app_id, env_id, profile_id, v2)

    appconfigdata = ctx.client("appconfigdata")

    def _start_and_fetch(_i):
        token = appconfigdata.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=profile_id,
        )["InitialConfigurationToken"]
        resp = appconfigdata.get_latest_configuration(ConfigurationToken=token)
        return resp["Configuration"].read()

    with ThreadPoolExecutor(max_workers=5) as pool:
        bodies = list(pool.map(_start_and_fetch, range(5)))

    assert all(body == v2_content for body in bodies), f"expected all pollers to see {v2_content!r}, got {bodies}"


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


def _create_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-acd-profile-"),
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
