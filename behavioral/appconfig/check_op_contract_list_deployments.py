"""op-contract-listDeployments."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listDeployments"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeployments enumerates the completed deployment with its exact
    DeploymentNumber and terminal State; a nonexistent EnvironmentId is rejected with
    ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    deployment = _create_completed_deployment(ctx, appconfig)

    items = appconfig.list_deployments(
        ApplicationId=deployment["app_id"], EnvironmentId=deployment["env_id"]
    )["Items"]
    matches = [i for i in items if i["DeploymentNumber"] == deployment["deployment_number"]]
    assert len(matches) == 1, f"expected exactly one matching deployment, got {matches}"
    assert matches[0]["State"] == "COMPLETE", f"expected COMPLETE, got {matches[0]['State']!r}"

    # error boundary: EnvironmentId never existed on this application
    err = _error(
        lambda: appconfig.list_deployments(
            ApplicationId=deployment["app_id"], EnvironmentId="zzzzzzzz"
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == (
        f"Environment with Application Id {deployment['app_id']} and Environment Id zzzzzzzz "
        f"could not be found for account {account}."
    ), f"unexpected message: {err['Message']!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a nonexistent EnvironmentId real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_completed_deployment(ctx, appconfig):
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-")
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-cp-"),
        LocationUri="hosted",
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = b'{"enabled": true}'
    content_type = "application/json"
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    started = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = started["DeploymentNumber"]

    def _probe():
        return appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )

    final = _poll_until(
        _probe, lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK"), timeout_s=120.0, interval_s=3.0
    )
    if final["State"] != "COMPLETE":
        raise AssertionError(f"deployment ended in unexpected state {final['State']}")

    return {
        "app_id": app_id,
        "env_id": env_id,
        "profile_id": profile_id,
        "strategy_id": strategy_id,
        "version_number": version_number,
        "content": content,
        "content_type": content_type,
        "deployment_number": deployment_number,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
