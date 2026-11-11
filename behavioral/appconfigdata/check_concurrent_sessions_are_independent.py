"""concurrent-sessions-are-independent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-sessions-are-independent"
GROUP = "concurrency"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfigdata-concurrent-sessions"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrently-started sessions on the same profile get independent, non-colliding token chains."""
    content = b'{"shared":true}'
    app_id, env_id, profile_id = _setup_deployed_profile(ctx, content=content, content_type="application/json")

    appconfigdata = ctx.client("appconfigdata")

    def _start():
        return appconfigdata.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=profile_id,
        )["InitialConfigurationToken"]

    with ThreadPoolExecutor(max_workers=3) as pool:
        tokens = list(pool.map(lambda _: _start(), range(3)))

    assert len(set(tokens)) == 3, "concurrently-started sessions must not share an initial token"

    def _fetch(token):
        resp = appconfigdata.get_latest_configuration(ConfigurationToken=token)
        return resp["Configuration"].read(), resp["NextPollConfigurationToken"]

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(_fetch, tokens))

    bodies = [body for body, _ in results]
    next_tokens = [nt for _, nt in results]

    assert all(body == content for body in bodies), "each independent session must see the full deployed content"
    assert len(set(next_tokens)) == 3, "each session's next-poll token must remain distinct from the others"


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
