"""appconfigdata-environment-configuration-isolation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-environment-configuration-isolation"
GROUP = "data-plane"
SERVICES = ["appconfigdata"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same configuration profile deployed with different content to two separate
    environments of the same application serves each environment's own deployed
    version independently through the data plane."""
    app_id = _create_application(ctx)
    env1_id = _create_environment(ctx, app_id)
    env2_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)
    strategy_id = _create_strategy(ctx)

    content1 = b'{"env": "one"}'
    content2 = b'{"env": "two"}'
    version1 = _create_hosted_version(ctx, app_id, profile_id, content1)
    version2 = _create_hosted_version(ctx, app_id, profile_id, content2)

    _deploy_and_wait(ctx, app_id, env1_id, profile_id, strategy_id, version1)
    _deploy_and_wait(ctx, app_id, env2_id, profile_id, strategy_id, version2)

    appconfigdata = ctx.client("appconfigdata")
    session1 = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env1_id,
        ConfigurationProfileIdentifier=profile_id,
    )
    session2 = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env2_id,
        ConfigurationProfileIdentifier=profile_id,
    )
    resp1 = appconfigdata.get_latest_configuration(
        ConfigurationToken=session1["InitialConfigurationToken"]
    )
    resp2 = appconfigdata.get_latest_configuration(
        ConfigurationToken=session2["InitialConfigurationToken"]
    )
    body1 = resp1["Configuration"].read()
    body2 = resp2["Configuration"].read()
    assert body1 == content1, f"env1 session expected {content1!r}, got {body1!r}"
    assert body2 == content2, f"env2 session expected {content2!r}, got {body2!r}"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags={"sim2real": "behavioral"}
    )["Id"]

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
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-"),
        Tags={"sim2real": "behavioral"},
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
        Tags={"sim2real": "behavioral"},
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
        Tags={"sim2real": "behavioral"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
