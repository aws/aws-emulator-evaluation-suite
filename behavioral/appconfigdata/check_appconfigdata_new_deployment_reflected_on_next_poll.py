"""appconfigdata-new-deployment-reflected-on-next-poll."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-new-deployment-reflected-on-next-poll"
GROUP = "state"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfigdata-new-deployment-reflected-on-next-poll"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A configuration change deployed after a session's first poll is visible on the
    very next GetLatestConfiguration call for that session, replacing the previously
    served payload."""
    content_v1 = b'{"version": 1}'
    content_v2 = b'{"version": 2}'
    setup = _full_setup(ctx, content_v1, content_type="application/json")

    appconfigdata = ctx.client("appconfigdata")
    session = appconfigdata.start_configuration_session(
        ApplicationIdentifier=setup["app_id"],
        EnvironmentIdentifier=setup["env_id"],
        ConfigurationProfileIdentifier=setup["profile_id"],
    )
    first = appconfigdata.get_latest_configuration(
        ConfigurationToken=session["InitialConfigurationToken"]
    )
    first_body = first["Configuration"].read()
    assert first_body == content_v1, f"expected initial poll to serve {content_v1!r}, got {first_body!r}"

    version2 = _create_hosted_version(ctx, setup["app_id"], setup["profile_id"], content_v2)
    _deploy_and_wait(
        ctx, setup["app_id"], setup["env_id"], setup["profile_id"], setup["strategy_id"], version2
    )

    # Poll until the new deployment propagates through the data plane. Each call
    # consumes the current token and mints the next one; empty Configuration means
    # "no change yet" and must be retried with the freshly minted token.
    token = first["NextPollConfigurationToken"]
    deadline = time.monotonic() + 60.0
    body = b""
    while time.monotonic() < deadline:
        resp = appconfigdata.get_latest_configuration(ConfigurationToken=token)
        token = resp["NextPollConfigurationToken"]
        body = resp["Configuration"].read()
        if body == content_v2:
            break
        time.sleep(3)
    assert body == content_v2, f"expected {content_v2!r} within 60s, last body={body!r}"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
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
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
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
        Tags=_TAGS,
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


def _full_setup(ctx, content, content_type="application/json", version_label=None):
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)
    strategy_id = _create_strategy(ctx)
    version_number = _create_hosted_version(ctx, app_id, profile_id, content, content_type, version_label)
    _deploy_and_wait(ctx, app_id, env_id, profile_id, strategy_id, version_number)
    return {
        "app_id": app_id,
        "env_id": env_id,
        "profile_id": profile_id,
        "strategy_id": strategy_id,
        "version_number": version_number,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
