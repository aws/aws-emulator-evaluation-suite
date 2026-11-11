"""appconfigdata-binary-content-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-binary-content-round-trip"
GROUP = "data-plane"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfigdata-binary-round-trip"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Arbitrary binary content (every byte value 0-255, not valid UTF-8) round-trips
    through the configuration data plane exactly, with no text-encoding corruption of
    the payload."""
    content = bytes(range(256))
    setup = _full_setup(ctx, content, content_type="application/octet-stream")

    appconfigdata = ctx.client("appconfigdata")
    session = appconfigdata.start_configuration_session(
        ApplicationIdentifier=setup["app_id"],
        EnvironmentIdentifier=setup["env_id"],
        ConfigurationProfileIdentifier=setup["profile_id"],
    )
    resp = appconfigdata.get_latest_configuration(
        ConfigurationToken=session["InitialConfigurationToken"]
    )
    served = resp["Configuration"].read()
    assert len(served) == len(content), (
        f"appconfigdata changed the payload LENGTH: served {len(served)} bytes for "
        f"{len(content)} deployed bytes -- a UTF-8 replacement or an escape of the NUL byte "
        f"both present exactly this way"
    )
    assert served == content, (
        f"appconfigdata served payload does not match the deployed bytes: first differing "
        f"offset {next((i for i, (a, b) in enumerate(zip(served, content)) if a != b), None)!r}"
    )
    assert b"\x00" in served, "NUL byte was stripped from the served payload"
    assert resp["ContentType"] == "application/octet-stream", (
        f"served ContentType is {resp['ContentType']!r}, expected 'application/octet-stream' -- "
        f"the data plane must not re-label a binary configuration"
    )


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]

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
        Tags=_TAGS,
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
