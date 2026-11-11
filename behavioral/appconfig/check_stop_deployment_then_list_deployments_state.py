"""stop-deployment-then-list-deployments-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-deployment-then-list-deployments-state"
GROUP = "deployment"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After StopDeployment the deployment shows ROLLED_BACK state consistently in both
    GetDeployment and ListDeployments."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    env_id = appconfig.create_environment(ApplicationId=app_id, Name="env-stop")["Id"]
    ctx.on_cleanup(lambda: _safe_delete_environment(appconfig, app_id, env_id))

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id, Name="cp-stop", LocationUri="hosted", Type="AWS.Freeform"
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"key": "value"}',
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(lambda: _safe_delete_version(appconfig, app_id, cp_id, version_number))

    # A slow (10-minute) linear rollout so we have time to interrupt it mid-flight.
    ds_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-"),
        DeploymentDurationInMinutes=10,
        GrowthFactor=10.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_strategy(appconfig, ds_id))

    started = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = started["DeploymentNumber"]
    assert started["State"] in ("BAKING", "VALIDATING", "DEPLOYING"), (
        f"expected an in-flight state (BAKING/VALIDATING/DEPLOYING) right after StartDeployment, "
        f"got {started['State']!r}"
    )

    stopped = appconfig.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
    )
    # StopDeployment on an in-flight (non-AllowRevert) deployment answers synchronously with
    # State="ROLLED_BACK" -- there is no observed transitional ROLLING_BACK response (measured
    # against real AWS in this suite's other stop-deployment checks; ROLLING_BACK is a modelled
    # enum member but not one StopDeployment itself has been seen to return).
    assert stopped["State"] == "ROLLED_BACK", (
        f"expected StopDeployment to answer State='ROLLED_BACK' synchronously, got "
        f"{stopped['State']!r}"
    )

    final = _poll_until(
        probe=lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        predicate=lambda d: d["State"] == "ROLLED_BACK",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["State"] == "ROLLED_BACK", (
        f"expected GetDeployment to settle on State='ROLLED_BACK', got {final['State']!r}"
    )

    items = _list_all_deployments(appconfig, app_id, env_id)
    match = next((i for i in items if i["DeploymentNumber"] == deployment_number), None)
    assert match is not None, "stopped deployment not found in ListDeployments"
    assert match["State"] == "ROLLED_BACK", f"ListDeployments shows stale state {match['State']!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last.get('State') if last else None}")


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


def _safe_delete_version(appconfig, app_id, cp_id, version_number):
    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version_number
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_strategy(appconfig, ds_id):
    try:
        appconfig.delete_deployment_strategy(DeploymentStrategyId=ds_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_deployments(appconfig, app_id, env_id):
    items = []
    kwargs = {"ApplicationId": app_id, "EnvironmentId": env_id}
    while True:
        resp = appconfig.list_deployments(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"ApplicationId": app_id, "EnvironmentId": env_id, "NextToken": token}
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
