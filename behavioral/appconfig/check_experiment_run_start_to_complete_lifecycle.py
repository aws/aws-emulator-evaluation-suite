"""experiment-run-start-to-complete-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-run-start-to-complete-lifecycle"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-lifecycle"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Starting a run transitions RUNNING->DONE; Get/List/Update reflect state throughout."""
    appconfig = ctx.client("appconfig")
    env = _create_experiment_ready_env(ctx)
    exp = _create_experiment_definition(ctx, env)
    exp_id = exp["Id"]

    before_start = appconfig.get_experiment_definition(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert before_start["Status"] == "IDLE", f"expected IDLE before any run, got {before_start['Status']}"

    started = _start_experiment_run(ctx, env["app_id"], exp_id, 10.0)
    run_number = started["Run"]
    assert started["Status"] == "RUNNING", f"expected RUNNING immediately after start, got {started['Status']}"
    assert started["ExposurePercentage"] == 10.0, (
        f"expected StartExperimentRun to echo the requested 10.0% exposure, got {started['ExposurePercentage']}"
    )

    got_run = appconfig.get_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert got_run["Status"] == "RUNNING", f"expected GetExperimentRun to reflect RUNNING, got {got_run['Status']}"
    assert got_run["ExposurePercentage"] == 10.0, (
        f"expected GetExperimentRun to reflect 10.0% exposure, got {got_run['ExposurePercentage']}"
    )

    active_def = appconfig.get_experiment_definition(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert active_def["Status"] == "ACTIVE", f"expected ACTIVE while run is RUNNING, got {active_def['Status']}"

    listed_runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )["Items"]
    assert run_number in [item["Run"] for item in listed_runs], (
        f"expected run {run_number} in ListExperimentRuns, got runs {[item['Run'] for item in listed_runs]}"
    )
    running_item = next(item for item in listed_runs if item["Run"] == run_number)
    assert running_item["Status"] == "RUNNING", (
        f"expected ListExperimentRuns entry for run {run_number} to show RUNNING, got {running_item['Status']}"
    )

    updated_run = appconfig.update_experiment_run(
        ApplicationIdentifier=env["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run_number,
        ExposurePercentage=50.0,
    )
    assert updated_run["ExposurePercentage"] == 50.0, (
        f"expected UpdateExperimentRun to echo the new 50.0% exposure, got {updated_run['ExposurePercentage']}"
    )
    assert updated_run["Status"] == "RUNNING", (
        f"expected run to remain RUNNING across an exposure update, got {updated_run['Status']}"
    )

    got_run_after_update = appconfig.get_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert got_run_after_update["ExposurePercentage"] == 50.0, (
        "expected GetExperimentRun to reflect the updated 50.0% exposure, "
        f"got {got_run_after_update['ExposurePercentage']}"
    )

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert stopped["Status"] == "DONE", f"expected DONE immediately after stop, got {stopped['Status']}"
    assert "EndedAt" in stopped, f"expected StopExperimentRun response to carry EndedAt, got keys {sorted(stopped)}"

    got_run_after_stop = appconfig.get_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert got_run_after_stop["Status"] == "DONE", (
        f"expected GetExperimentRun to reflect DONE after stop, got {got_run_after_stop['Status']}"
    )

    idle_def = appconfig.get_experiment_definition(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert idle_def["Status"] == "IDLE", f"expected IDLE after run stopped, got {idle_def['Status']}"

    listed_runs_final = appconfig.list_experiment_runs(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )["Items"]
    final_item = next(item for item in listed_runs_final if item["Run"] == run_number)
    assert final_item["Status"] == "DONE", (
        f"expected ListExperimentRuns entry for run {run_number} to show DONE, got {final_item['Status']}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _create_experiment_ready_env(ctx) -> dict[str, str]:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )

    flag_key = "simflag"
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]

    # StartExperimentRun requires an existing (completed) deployment for the configuration
    # profile in the target environment, so deploy the hosted version before returning.
    #
    # The predefined strategy "AppConfig.AllAtOnce" carries a 10-minute
    # FinalBakeTimeInMinutes, so a deployment using it sits in the "BAKING" state
    # for ~600s before reaching "COMPLETE" -- on its own that blows past the
    # harness's 300s budget for the whole check. Use a custom strategy with zero
    # deployment duration and zero bake time so the deployment (and the
    # environment settling back to ready) completes in seconds, not minutes.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    # GetDeployment.State and GetEnvironment.State are NOT cased consistently. The Smithy
    # model documents both as SCREAMING_SNAKE_CASE, and the deployment's wire value matches
    # that ("COMPLETE") -- but the environment's wire value comes back PascalCase
    # ("ReadyForDeployment"), diverging from its own model. Each poll must use the casing
    # its own operation actually returns.
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment["DeploymentNumber"]
        )["State"],
        lambda state: state == "COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    # The deployment reaching COMPLETE can still lag behind the environment's own
    # State settling back to ReadyForDeployment. StartExperimentRun rejects with
    # ConflictException while the environment reports Deploying, so wait for it
    # directly here rather than relying solely on the retry loop in _start_experiment_run.
    _poll_until(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"],
        lambda state: state == "ReadyForDeployment",
        timeout_s=120.0,
        interval_s=3.0,
    )
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _start_experiment_run(
    ctx, app_id: str, exp_id: str, exposure_pct: float, *, timeout_s: float = 300.0, interval_s: float = 3.0
):
    """Start an experiment run, retrying on ConflictException.

    The environment's own State can lag behind its deployment reaching COMPLETE
    (it briefly reports as still deploying), and StartExperimentRun rejects with
    ConflictException until the environment has settled back to ready. Poll the
    real operation itself -- bounded -- rather than guessing at a settling delay.
    """
    appconfig = ctx.client("appconfig")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appconfig.start_experiment_run(
                ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, ExposurePercentage=exposure_pct
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_experiment_definition(ctx, env: dict[str, str]) -> dict[str, Any]:
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=env["app_id"],
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=env["profile_id"],
        EnvironmentIdentifier=env["env_id"],
        FlagKey=env["flag_key"],
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": False}, "Weight": 50},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": 50}],
        Tags=_TAGS,
    )
    exp_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment(ctx, env["app_id"], exp_id))
    return resp


def _safe_delete_experiment(ctx, app_id: str, exp_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

