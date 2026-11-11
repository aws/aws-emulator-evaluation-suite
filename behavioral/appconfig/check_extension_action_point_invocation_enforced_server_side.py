"""extension-action-point-invocation-enforced-server-side."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "extension-action-point-invocation-enforced-server-side"
GROUP = "server-side"
SERVICES = ["appconfig"]
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-extension-action-point-server-side"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An extension associated with the environment's ON_DEPLOYMENT_START action point is
    recorded by the service in StartDeployment's AppliedExtensions and persists in GetDeployment,
    though the client only calls StartDeployment.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    env_arn = _env_arn(ctx, app_id, env_id)

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS")))

    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=b'{"greeting": "hello"}',
        ContentType="application/json",
    )["VersionNumber"]

    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={"ON_DEPLOYMENT_START": [
            {"Name": "log-start", "Uri": f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-log"},
        ]},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=env_arn, Tags=_TAGS)
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)))

    # Zero duration/bake avoids AppConfig.AllAtOnce's ~10 min FinalBakeTimeInMinutes.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)))

    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = deployment["DeploymentNumber"]

    applied = deployment.get("AppliedExtensions", [])
    matches = [a for a in applied if a["ExtensionId"] == ext_id and a["ExtensionAssociationId"] == assoc_id]
    assert matches, (
        f"StartDeployment response did not record our extension as server-side applied: {applied}"
    )

    final = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number),
        lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK", "REVERTED"),
        timeout_s=90.0,
        interval_s=3.0,
    )

    persisted = [
        a for a in final.get("AppliedExtensions", [])
        if a["ExtensionId"] == ext_id and a["ExtensionAssociationId"] == assoc_id
    ]
    assert persisted, "GetDeployment lost the server-recorded extension invocation after the deployment completed"


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _env_arn(ctx, app_id, env_id):
    return f"arn:aws:appconfig:{ctx.region}:{_account_id(ctx)}:application/{app_id}/environment/{env_id}"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_environment(
        ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS")))
    return env_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
