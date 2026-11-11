"""appconfigdata-cross-application-profile-mismatch-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-cross-application-profile-mismatch-not-found"
GROUP = "overly-permissive"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A session naming a configuration profile that belongs to a different application in the same
    account is treated as not found: isolation holds across applications, not only accounts.
    """
    content = b'{"app": "one"}'
    setup1 = _full_setup(ctx, content, content_type="application/json")

    app2_id = _create_application(ctx)
    profile2_id = _create_profile(ctx, app2_id)

    appconfigdata = ctx.client("appconfigdata")
    code, message = _client_error(
        lambda: appconfigdata.start_configuration_session(
            ApplicationIdentifier=setup1["app_id"],
            EnvironmentIdentifier=setup1["env_id"],
            ConfigurationProfileIdentifier=profile2_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException when starting a session against app1's "
        f"application/environment pair with app2's configuration profile, got {code!r}"
    )
    assert message == "ConfigurationProfile not found", f"expected message 'ConfigurationProfile not found', got {message!r}"

    # positive control: the matching (application, environment, profile) triple works --
    # proved by an independent read (GetLatestConfiguration), not the session call's own
    # response envelope, so this cannot pass merely because StartConfigurationSession
    # echoed a token back.
    session = appconfigdata.start_configuration_session(
        ApplicationIdentifier=setup1["app_id"],
        EnvironmentIdentifier=setup1["env_id"],
        ConfigurationProfileIdentifier=setup1["profile_id"],
    )
    resp = appconfigdata.get_latest_configuration(
        ConfigurationToken=session["InitialConfigurationToken"]
    )
    body = resp["Configuration"].read()
    assert body == content, (
        f"matching (application, environment, profile) triple should serve the "
        f"deployed content {content!r}, got {body!r}"
    )


def _client_error(fn):
    """Return (code, message) for a call that must be refused.

    Raises AssertionError when the call succeeds: an emulator that accepts what AWS refuses
    must fail loudly, not read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


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
