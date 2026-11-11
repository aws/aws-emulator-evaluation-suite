"""experiment-definition-create-active-delete-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-definition-create-active-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-lifecycle"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An experiment definition goes IDLE -> ACTIVE -> IDLE as a run starts and stops, visible via
    Get and List; after DeleteExperimentDefinition, Get and a mutation fail with the not-found code
    and List no longer holds the id.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)

    def_id, created = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)
    assert created["Status"] == "IDLE", f"new experiment definition must start IDLE, got {created['Status']!r}"

    got = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert got["Id"] == def_id, f"expected Get to return {def_id!r}, got {got['Id']!r}"
    assert got["Status"] == "IDLE", f"expected IDLE via independent Get, got {got['Status']!r}"

    listed = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)
    assert any(item["Id"] == def_id for item in listed["Items"]), (
        f"{def_id} missing from ListExperimentDefinitions before any run started"
    )

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = run_resp["Run"]
    assert run_resp["Status"] == "RUNNING", f"expected StartExperimentRun to return RUNNING, got {run_resp['Status']!r}"

    active = _poll_until(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        ),
        lambda resp: resp["Status"] == "ACTIVE",
        timeout_s=30.0,
    )
    assert active["Status"] == "ACTIVE", f"expected ACTIVE while a run is in progress, got {active['Status']!r}"

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )

    idle_again = _poll_until(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        ),
        lambda resp: resp["Status"] == "IDLE",
        timeout_s=30.0,
    )
    assert idle_again["Status"] == "IDLE", f"expected IDLE once the run stopped, got {idle_again['Status']!r}"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment "
        f"Definition Identifier {def_id} could not be found for account {account_id}."
    )
    get_code, get_message = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get after delete, got {get_code!r}"
    )
    assert get_message == not_found, f"expected {not_found!r}, got {get_message!r}"

    mutate_code, mutate_message = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected StartExperimentRun against the deleted definition to 404, got {mutate_code!r}"
    )
    assert mutate_message == not_found, f"expected {not_found!r}, got {mutate_message!r}"

    listed_after = _poll_until(
        lambda: appconfig.list_experiment_definitions(ApplicationIdentifier=app_id),
        lambda resp: all(item["Id"] != def_id for item in resp["Items"]),
        timeout_s=20.0,
    )
    assert all(item["Id"] != def_id for item in listed_after["Items"]), (
        f"{def_id} still present in ListExperimentDefinitions after delete"
    )


def _flag_key() -> str:
    return "flag" + uuid.uuid4().hex[:10]


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str):
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: _delete_profile_and_versions(
            appconfig, ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS"
        )
    )
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": False}},
            "version": "1",
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id: str, env_id: str, profile_id: str, version_number) -> int:
    """Start (and wait for completion of) a deployment of the configuration profile version to
    the environment, using a custom zero-duration/zero-bake deployment strategy so it reaches
    COMPLETE quickly. AppConfig requires an existing, completed deployment for a configuration
    profile before an experiment run can be started against the feature flag it stores (a
    RUNNING deployment leaves the environment in state DEPLOYING, which StartExperimentRun
    rejects)."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )
    strategy_id = strategy["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    dep = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = dep["DeploymentNumber"]
    completed = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda resp: resp["State"] == "COMPLETE",
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert completed["State"] == "COMPLETE"
    return deployment_number


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key, name=None):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, def_id))
    return def_id, resp


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS
    raises, because a target ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_profile_and_versions(appconfig, **profile):
    """Teardown: delete every hosted version, then the profile, because AWS refuses to delete a
    configuration profile that still has hosted versions."""
    ids = {
        "ApplicationId": profile["ApplicationId"],
        "ConfigurationProfileId": profile["ConfigurationProfileId"],
    }
    for page in appconfig.get_paginator("list_hosted_configuration_versions").paginate(**ids):
        for item in page["Items"]:
            appconfig.delete_hosted_configuration_version(**ids, VersionNumber=item["VersionNumber"])
    appconfig.delete_configuration_profile(**profile)


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
