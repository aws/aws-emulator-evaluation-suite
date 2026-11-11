"""appconfigdata-first-poll-returns-deployed-configuration."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-first-poll-returns-deployed-configuration"
GROUP = "data-plane"
SERVICES = ["appconfigdata"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfigdata-first-poll"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """First GetLatestConfiguration call on a fresh session returns the deployed hosted
    configuration content byte-for-byte, with the matching ContentType and a fresh poll
    token/interval."""
    marker = uuid.uuid4().hex
    content = json.dumps({"enabled": True, "marker": marker}).encode()
    setup = _full_setup(ctx, content, content_type="application/json")

    appconfigdata = ctx.client("appconfigdata")
    session = appconfigdata.start_configuration_session(
        ApplicationIdentifier=setup["app_id"],
        EnvironmentIdentifier=setup["env_id"],
        ConfigurationProfileIdentifier=setup["profile_id"],
    )
    initial_token = session["InitialConfigurationToken"]

    resp = appconfigdata.get_latest_configuration(ConfigurationToken=initial_token)
    body = resp["Configuration"].read()

    assert body == content, f"expected deployed content {content!r}, got {body!r}"
    assert resp["ContentType"] == "application/json", (
        f"expected ContentType 'application/json', got {resp['ContentType']!r}"
    )
    assert resp["NextPollConfigurationToken"] != initial_token, (
        "expected NextPollConfigurationToken to differ from the initial token, got the same value"
    )
    interval = resp["NextPollIntervalInSeconds"]
    assert isinstance(interval, int), f"expected NextPollIntervalInSeconds to be an int, got {interval!r}"
    assert interval > 0, f"expected NextPollIntervalInSeconds > 0, got {interval!r}"

    # A second poll on the rotated token, with nothing redeployed, carries no configuration.
    again = appconfigdata.get_latest_configuration(ConfigurationToken=resp["NextPollConfigurationToken"])
    unchanged = again["Configuration"].read()
    assert unchanged == b"", f"expected an empty Configuration on an unchanged re-poll, got {unchanged!r}"

    # Teardown in the check, bottom-up, then prove the parent application is gone on the control
    # plane. The data plane is not probed after the delete: AWS keeps serving a session briefly.
    appconfig = ctx.client("appconfig")
    app_id = setup["app_id"]
    appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=setup["profile_id"],
        VersionNumber=setup["version_number"],
    )
    appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=setup["profile_id"],
        DeletionProtectionCheck="BYPASS",
    )
    appconfig.delete_environment(
        ApplicationId=app_id, EnvironmentId=setup["env_id"], DeletionProtectionCheck="BYPASS"
    )
    appconfig.delete_application(ApplicationId=app_id)
    appconfig.delete_deployment_strategy(DeploymentStrategyId=setup["strategy_id"])
    try:
        appconfig.get_application(ApplicationId=app_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = exc.response.get("Error", {}).get("Message") or ""
    else:
        raise AssertionError(f"GetApplication({app_id}) still resolves after DeleteApplication")
    assert code == "ResourceNotFoundException", f"GetApplication after delete: got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"GetApplication after delete: expected HTTP 4xx, got {status!r}"
    expected_message = f"Application with Id {app_id} could not be found for account {ctx.account}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed = [
        a["Id"]
        for page in appconfig.get_paginator("list_applications").paginate()
        for a in page.get("Items", [])
    ]
    assert app_id not in listed, f"deleted application {app_id!r} is still listed by ListApplications"
    # Beat 3: a write to the dead application is refused with the same not-found code.
    try:
        appconfig.update_application(ApplicationId=app_id, Description="after-delete")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = exc.response.get("Error", {}).get("Message") or ""
    else:
        raise AssertionError(f"UpdateApplication({app_id}) succeeded after DeleteApplication")
    assert code == "ResourceNotFoundException", (
        f"UpdateApplication after delete: expected ResourceNotFoundException, got {code!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"UpdateApplication after delete: expected HTTP 4xx, got {status!r}"
    expected_message = f"Application with Id {app_id} could not be found for account {ctx.account}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]

    def _cleanup():
        try:
            appconfig.delete_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
            appconfig.delete_environment(
                ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
                ApplicationId=app_id, ConfigurationProfileId=profile_id,
                DeletionProtectionCheck="BYPASS",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
