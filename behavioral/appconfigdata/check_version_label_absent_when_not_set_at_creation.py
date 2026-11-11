"""version-label-absent-when-not-set-at-creation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "version-label-absent-when-not-set-at-creation"
GROUP = "config-delivery"
SERVICES = ["appconfigdata"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLatestConfiguration for a hosted version created without a VersionLabel carries no label,
    while a sibling version created with one echoes it (positive control).
    """
    content = b'{"unlabelled":true}'
    app_id, env_id, profile_id = _setup_deployed_profile(ctx, content=content, content_type="application/json")

    label = "sim2real-acd-label-control"
    labelled_content = b'{"unlabelled":false}'
    labelled_profile_id = _create_profile(ctx, app_id)
    labelled_version_number = _create_hosted_version(
        ctx, app_id, labelled_profile_id, labelled_content, "application/json", version_label=label
    )
    _deploy_version(ctx, app_id, env_id, labelled_profile_id, labelled_version_number)

    appconfigdata = ctx.client("appconfigdata")
    initial_token = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
    )["InitialConfigurationToken"]

    resp = appconfigdata.get_latest_configuration(ConfigurationToken=initial_token)

    body = resp["Configuration"].read()
    assert body == content, f"expected deployed content {content!r}, got {body!r}"
    assert not resp.get("VersionLabel"), f"expected no VersionLabel, got {resp.get('VersionLabel')!r}"

    labelled_token = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=labelled_profile_id,
    )["InitialConfigurationToken"]
    labelled_resp = appconfigdata.get_latest_configuration(ConfigurationToken=labelled_token)
    labelled_body = labelled_resp["Configuration"].read()
    assert labelled_body == labelled_content, f"expected deployed content {labelled_content!r}, got {labelled_body!r}"
    assert labelled_resp.get("VersionLabel") == label, (
        f"positive control: expected VersionLabel {label!r} on a version created WITH a label, "
        f"got {labelled_resp.get('VersionLabel')!r} -- without this, a target that never implements "
        f"VersionLabel would also pass the absence assertion above"
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
