"""get-configuration-nonexistent-profile-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-configuration-nonexistent-profile-not-found"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-configuration-not-found"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConfiguration rejects an unknown Application, Environment or profile, and a triple with
    nothing deployed, with BadRequestException (not ResourceNotFoundException) echoing the ids;
    once a deployment completes the same call returns the deployed bytes."""
    appconfig = ctx.client("appconfig")
    account = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name="env-gc", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_environment(appconfig, app_id, env_id))

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id, Name="cp-gc", LocationUri="hosted", Type="AWS.Freeform", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    client_id = ctx.unique_name("client-")
    fake_app = "sim2real-nonexistent-app-xyz"
    fake_env = "sim2real-nonexistent-env-xyz"
    fake_cfg = "sim2real-nonexistent-profile-xyz"

    # GetConfiguration resolves the (Application, Configuration) pair first.
    err_app = _error(
        lambda: appconfig.get_configuration(
            Application=fake_app, Environment=env_id, Configuration=cp_id, ClientId=client_id,
        )
    )
    assert err_app["Code"] == "BadRequestException", (
        f"expected BadRequestException for an unknown Application, got {err_app['Code']!r}"
    )
    assert err_app["Message"] == (
        f"Configuration Profile with Application Id {fake_app} and Configuration Profile Id "
        f"{cp_id} could not be found for account {account}."
    ), f"unexpected message for an unknown Application: {err_app['Message']!r}"

    # Environment is only used to look up a deployment, so an unknown one gets the same
    # "No deployed version" message as a real Environment with nothing deployed.
    err_env = _error(
        lambda: appconfig.get_configuration(
            Application=app_id, Environment=fake_env, Configuration=cp_id, ClientId=client_id,
        )
    )
    assert err_env["Code"] == "BadRequestException", (
        f"expected BadRequestException for an unknown Environment, got {err_env['Code']!r}"
    )
    assert err_env["Message"] == (
        f"No deployed version for configuration profile {cp_id} in environment {fake_env} "
        f"and app {app_id}"
    ), f"unexpected message for an unknown Environment: {err_env['Message']!r}"

    err_cfg = _error(
        lambda: appconfig.get_configuration(
            Application=app_id, Environment=env_id, Configuration=fake_cfg, ClientId=client_id,
        )
    )
    assert err_cfg["Code"] == "BadRequestException", (
        f"expected BadRequestException for an unknown Configuration, got {err_cfg['Code']!r}"
    )
    assert err_cfg["Message"] == (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id "
        f"{fake_cfg} could not be found for account {account}."
    ), f"unexpected message for an unknown Configuration: {err_cfg['Message']!r}"

    err_nodeploy = _error(
        lambda: appconfig.get_configuration(
            Application=app_id, Environment=env_id, Configuration=cp_id, ClientId=client_id,
        )
    )
    assert err_nodeploy["Code"] == "BadRequestException", (
        f"expected BadRequestException before any deployment, got {err_nodeploy['Code']!r}"
    )
    assert err_nodeploy["Message"] == (
        f"No deployed version for configuration profile {cp_id} in environment {env_id} "
        f"and app {app_id}"
    ), f"unexpected message before any deployment: {err_nodeploy['Message']!r}"

    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_strategy(appconfig, strategy_id))

    content = b'{"enabled": true}'
    content_type = "application/json"
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, Content=content, ContentType=content_type,
    )["VersionNumber"]
    ctx.on_cleanup(lambda: _safe_delete_version(appconfig, app_id, cp_id, version_number))

    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]

    final = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["State"] == "COMPLETE", f"deployment ended in unexpected state {final['State']!r}"

    resp = appconfig.get_configuration(
        Application=app_id, Environment=env_id, Configuration=cp_id, ClientId=client_id,
    )
    assert resp["Content"].read() == content, (
        "the identical GetConfiguration call did not return the deployed content once a "
        "deployment actually completed"
    )
    assert resp["ContentType"] == content_type, (
        f"expected ContentType {content_type!r}, got {resp['ContentType']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a client error, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe_delete_strategy(appconfig, strategy_id):
    try:
        appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_version(appconfig, app_id, cp_id, version_number):
    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version_number
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_environment(appconfig, app_id, env_id):
    try:
        appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_profile(appconfig, app_id, cp_id):
    try:
        appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
