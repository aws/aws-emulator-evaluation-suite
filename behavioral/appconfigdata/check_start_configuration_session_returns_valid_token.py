"""start-configuration-session-returns-valid-token."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-configuration-session-returns-valid-token"
GROUP = "state"
SERVICES = ["appconfigdata"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartConfigurationSession returns a well-formed, usable InitialConfigurationToken."""
    app_id, env_id, profile_id = _setup_deployed_profile(
        ctx, b'{"flag": true}', "application/json"
    )
    data = ctx.client("appconfigdata")
    resp = data.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
    )
    token = resp["InitialConfigurationToken"]
    assert isinstance(token, str) and token, f"expected a non-empty str InitialConfigurationToken, got {token!r}"
    assert re.fullmatch(r"\S{1,8192}", token), f"token does not match expected pattern: {token!r}"

    # The token must actually be usable against GetLatestConfiguration.
    get_resp = data.get_latest_configuration(ConfigurationToken=token)
    body = get_resp["Configuration"].read()
    assert body == b'{"flag": true}', f"expected deployed content b'{{\"flag\": true}}', got {body!r}"


# ===== helpers =====
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")


def _safe(fn) -> None:
    """Run a teardown call; only an already-gone resource counts as clean."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _stop_and_settle(appcfg, app_id, env_id, deployment_number, timeout_s=60.0):
    """Stop a still-active deployment and wait for a terminal state: an environment that is
    deploying or rolling back refuses deletion."""
    ids = {"ApplicationId": app_id, "EnvironmentId": env_id, "DeploymentNumber": deployment_number}
    if appcfg.get_deployment(**ids)["State"] in _TERMINAL:
        return
    appcfg.stop_deployment(AllowRevert=True, **ids)
    deadline = time.monotonic() + timeout_s
    while (state := appcfg.get_deployment(**ids)["State"]) not in _TERMINAL:
        if time.monotonic() >= deadline:
            raise AssertionError(f"deployment {deployment_number} still {state} after {timeout_s}s")
        time.sleep(2.0)


def _create_application(ctx):
    appcfg = ctx.client("appconfig")
    resp = appcfg.create_application(Name=ctx.unique_name("sim2real-acd-app-"))
    app_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: appcfg.delete_application(ApplicationId=app_id)))
    return app_id, resp["Name"]


def _create_environment(ctx, app_id):
    appcfg = ctx.client("appconfig")
    resp = appcfg.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-acd-env-"))
    env_id = resp["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: appcfg.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    )
    return env_id, resp["Name"]


def _create_profile(ctx, app_id):
    appcfg = ctx.client("appconfig")
    resp = appcfg.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-acd-profile-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
    )
    profile_id = resp["Id"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appcfg.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        )
    )
    return profile_id, resp["Name"]


def _create_hosted_version(ctx, app_id, profile_id, content, content_type, version_label=None):
    appcfg = ctx.client("appconfig")
    kwargs = {
        "ApplicationId": app_id,
        "ConfigurationProfileId": profile_id,
        "Content": content,
        "ContentType": content_type,
    }
    if version_label:
        kwargs["VersionLabel"] = version_label
    version_number = appcfg.create_hosted_configuration_version(**kwargs)["VersionNumber"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appcfg.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
            )
        )
    )
    return version_number


def _deploy_and_wait(ctx, app_id, env_id, profile_id, version_number, timeout_s=60.0):
    appcfg = ctx.client("appconfig")
    deployment_number = appcfg.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId="AppConfig.AllAtOnce",
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    ctx.on_cleanup(
        lambda: _safe(lambda: _stop_and_settle(appcfg, app_id, env_id, deployment_number))
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dep = appcfg.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if dep.get("PercentageComplete", 0.0) >= 100.0:
            return deployment_number
        time.sleep(2.0)
    raise AssertionError(f"deployment {deployment_number} never reached 100% rollout within {timeout_s}s")


def _setup_deployed_profile(ctx, content, content_type, version_label=None):
    app_id, _ = _create_application(ctx)
    env_id, _ = _create_environment(ctx, app_id)
    profile_id, _ = _create_profile(ctx, app_id)
    version_number = _create_hosted_version(ctx, app_id, profile_id, content, content_type, version_label)
    _deploy_and_wait(ctx, app_id, env_id, profile_id, version_number)
    return app_id, env_id, profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
