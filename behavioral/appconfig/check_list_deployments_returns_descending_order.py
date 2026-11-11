"""list-deployments-returns-descending-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-deployments-returns-descending-order"
GROUP = "ordering"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-deployments-order"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeployments returns deployments ordered by descending deployment number
    (most recently started first)."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name="env-order", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_environment(appconfig, app_id, env_id))

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name="cp-order",
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    # Fully immediate rollout (0-minute duration, 100% growth, no bake) so each deployment
    # completes almost instantly and the next one can start (only one deployment may be
    # in-flight per environment at a time).
    ds_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_strategy(appconfig, ds_id))

    deployment_numbers = []
    for i in (1, 2, 3):
        version_number = appconfig.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=f'{{"n": {i}}}'.encode("utf-8"),
            ContentType="application/json",
        )["VersionNumber"]
        ctx.on_cleanup(lambda v=version_number: _safe_delete_version(appconfig, app_id, cp_id, v))

        started = appconfig.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(version_number),
        )
        deployment_number = started["DeploymentNumber"]
        deployment_numbers.append(deployment_number)

        _poll_until(
            probe=lambda dn=deployment_number: appconfig.get_deployment(
                ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dn
            ),
            predicate=lambda d: d["State"] == "COMPLETE",
            timeout_s=90.0,
            interval_s=3.0,
        )

    assert deployment_numbers == sorted(deployment_numbers), "deployment numbers should increase monotonically"

    items = _list_all_deployments(appconfig, app_id, env_id)
    listed_numbers = [i["DeploymentNumber"] for i in items]
    assert set(deployment_numbers).issubset(set(listed_numbers)), (
        f"expected all started deployment numbers {deployment_numbers} to appear in "
        f"ListDeployments, got {listed_numbers}"
    )
    assert listed_numbers == sorted(listed_numbers, reverse=True), (
        f"expected ListDeployments in descending deployment-number order, got {listed_numbers}"
    )
    assert listed_numbers[0] == deployment_numbers[-1], "most recently started deployment must be first"


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
