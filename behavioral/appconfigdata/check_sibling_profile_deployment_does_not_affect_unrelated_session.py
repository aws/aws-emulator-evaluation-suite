"""sibling-profile-deployment-does-not-affect-unrelated-session."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sibling-profile-deployment-does-not-affect-unrelated-session"
GROUP = "session-lifecycle"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deploying new content to a sibling configuration profile in the same app/env
    must not be visible on an active session that belongs to a different profile."""
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)

    profile_a = _create_profile(ctx, app_id)
    content_a = b'{"profile":"a"}'
    version_a = _create_hosted_version(ctx, app_id, profile_a, content_a, "application/json")
    _deploy_version(ctx, app_id, env_id, profile_a, version_a)

    profile_b = _create_profile(ctx, app_id)
    content_b1 = b'{"profile":"b","v":1}'
    version_b1 = _create_hosted_version(ctx, app_id, profile_b, content_b1, "application/json")
    _deploy_version(ctx, app_id, env_id, profile_b, version_b1)

    appconfigdata = ctx.client("appconfigdata")
    session_a = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_a,
    )["InitialConfigurationToken"]

    first_a = appconfigdata.get_latest_configuration(ConfigurationToken=session_a)
    first_a_body = first_a["Configuration"].read()
    assert first_a_body == content_a, f"expected profile A's initial poll to serve {content_a!r}, got {first_a_body!r}"
    token_a = first_a["NextPollConfigurationToken"]

    # break exactly one thing: deploy a NEW version to the sibling profile B, not A
    content_b2 = b'{"profile":"b","v":2}'
    version_b2 = _create_hosted_version(ctx, app_id, profile_b, content_b2, "application/json")
    _deploy_version(ctx, app_id, env_id, profile_b, version_b2)

    # profile A's session must see "no change", never profile B's new content
    second_a = appconfigdata.get_latest_configuration(ConfigurationToken=token_a)
    second_a_body = second_a["Configuration"].read()
    assert second_a_body == b"", (
        f"profile A's session must be unaffected by profile B's deployment, "
        f"expected empty (no-change) body, got {second_a_body!r}"
    )

    # positive control: profile B's own session does see its new content
    session_b = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_b,
    )["InitialConfigurationToken"]
    first_b = appconfigdata.get_latest_configuration(ConfigurationToken=session_b)
    first_b_body = first_b["Configuration"].read()
    assert first_b_body == content_b2, (
        f"expected profile B's own session to see its new deployment {content_b2!r}, got {first_b_body!r}"
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
