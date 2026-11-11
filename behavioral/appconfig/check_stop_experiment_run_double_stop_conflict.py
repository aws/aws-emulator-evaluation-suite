"""stop-experiment-run-double-stop-conflict."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-experiment-run-double-stop-conflict"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-stop-experiment-run-double-stop-conflict"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Stopping an already-DONE experiment run returns BadRequestException, not idempotent success."""
    appconfig = ctx.client("appconfig")
    env = _create_experiment_ready_env(ctx)
    exp = _create_experiment_definition(ctx, env)
    exp_id = exp["Id"]

    started = _start_experiment_run(ctx, env["app_id"], exp_id, 10.0)
    run_number = started["Run"]

    # Positive control: the first stop succeeds and transitions RUNNING -> DONE.
    first_stop = appconfig.stop_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert first_stop["Status"] == "DONE", f"expected first stop to transition to DONE, got {first_stop['Status']!r}"
    ended_at_first = first_stop["EndedAt"]

    # StopExperimentRun's synchronous response reports DONE immediately, but the
    # conflict guard on a second StopExperimentRun call appears to consult a
    # separate, eventually-consistent index of run statuses rather than the run
    # item itself. Poll that index directly (bounded) so the negative assertion
    # below isn't racing its own propagation delay and hitting a spurious success.
    _poll_until(
        lambda: appconfig.list_experiment_runs(
            ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Status="DONE"
        )["Items"],
        lambda items: any(item["Run"] == run_number for item in items),
        timeout_s=30.0,
        interval_s=2.0,
    )

    # Stop the already-DONE run again. Real AppConfig rejects this with BadRequestException
    # (the run is no longer in a stoppable state) rather than treating it as an idempotent
    # no-op or as ConflictException.
    second_stop_error = None
    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    except ClientError as err:
        second_stop_error = err.response["Error"]
    else:
        raise AssertionError(
            "expected StopExperimentRun on an already-DONE run to be rejected, but it succeeded"
        )

    assert second_stop_error["Code"] == "BadRequestException", (
        f"expected BadRequestException on double-stop, got {second_stop_error!r}"
    )
    expected_message = f"Experiment run {run_number} for experiment definition {exp_id} is not running."
    assert second_stop_error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {second_stop_error['Message']!r}"
    )

    # The run's terminal state must not have been mutated by the rejected repeat stop call.
    got_run = appconfig.get_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert got_run["Status"] == "DONE", f"expected DONE, got {got_run['Status']!r}"
    assert got_run["EndedAt"] == ended_at_first, "EndedAt must be unchanged by the repeated stop call"


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
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
    # DeleteConfigurationProfile is refused while a hosted version survives; LIFO runs this first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    # StartExperimentRun requires an existing (completed) deployment for the configuration
    # profile in the target environment, so deploy the hosted version before returning.
    #
    # The predefined strategy "AppConfig.AllAtOnce" carries a 10-minute
    # FinalBakeTimeInMinutes, so a deployment using it sits in the "Baking" state
    # for ~600s before reaching "Complete" -- on its own that blows past the
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
    # NOTE: despite the API documentation showing these enums in SCREAMING_SNAKE_CASE
    # (e.g. COMPLETE, READY_FOR_DEPLOYMENT), the actual wire values returned by the
    # service are PascalCase ("Complete", "ReadyForDeployment") -- confirmed against
    # real AWS. Polling for the documented-but-wrong casing never matches, so both
    # waits below previously burned their *entire* timeout budget on every run before
    # falling through to the start_experiment_run retry loop, which is what caused the
    # overall check to blow past the harness's time budget.
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment["DeploymentNumber"]
        )["State"],
        lambda state: state == "Complete",
        timeout_s=60.0,
        interval_s=2.0,
    )
    # The deployment reaching Complete can still lag behind the environment's own
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
