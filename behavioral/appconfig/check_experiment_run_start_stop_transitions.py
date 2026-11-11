"""experiment-run-start-stop-transitions."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags

CHECK = "experiment-run-start-stop-transitions"
GROUP = "state-machine"
SERVICES = ["appconfig"]
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-start-stop-transitions"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun -> RUNNING, StopExperimentRun -> DONE, each reflected by GetExperimentRun."""
    appconfig = ctx.client("appconfig")
    flag_key = ctx.unique_name("flag-")
    base = _create_base(ctx, flag_key)
    definition = _create_experiment_definition(ctx, base, flag_key)
    app_id = base["app_id"]
    def_id = definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_definition(appconfig, app_id, def_id))

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = started["Run"]
    assert started["Status"] == "RUNNING", f"expected RUNNING from StartExperimentRun, got {started['Status']}"
    assert started.get("EndedAt") is None, f"expected no EndedAt on a running run, got {started.get('EndedAt')}"

    fetched_running = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert fetched_running["Status"] == "RUNNING", (
        f"expected GetExperimentRun to independently confirm RUNNING, got {fetched_running['Status']}"
    )
    assert fetched_running.get("EndedAt") is None, (
        f"expected no EndedAt on a running run via independent read, got {fetched_running.get('EndedAt')}"
    )

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert stopped["Status"] == "DONE", f"expected DONE from StopExperimentRun, got {stopped['Status']}"
    assert stopped.get("EndedAt") is not None, "expected EndedAt to be set once the run is DONE"

    fetched_done = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert fetched_done["Status"] == "DONE", (
        f"expected GetExperimentRun to independently confirm DONE, got {fetched_done['Status']}"
    )
    assert fetched_done.get("EndedAt") is not None, "expected EndedAt to persist on independent read after stop"


# ===== helpers =====

def _error_code(fn):
    try:
        fn()
        return None
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"]


def _safe_delete_definition(appconfig, app_id, def_id, timeout_s=30.0):
    """Retry on ConflictException: DeleteType=DESTROY can be briefly refused right after
    StopExperimentRun, while AWS is still settling the run's terminal state."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
            )
            return
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number, timeout=90.0):
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        deployment = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        last_state = deployment["State"]
        if last_state == "COMPLETE":
            return
        if last_state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state {last_state}")
        time.sleep(3)
    raise AssertionError(
        f"deployment did not reach COMPLETE within {timeout}s (last state {last_state})"
    )


def _create_base(ctx, flag_key):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="BYPASS",
        )
    )

    content = json.dumps(
        {
            "version": "1",
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    # DeleteConfigurationProfile is refused while a hosted version exists: LIFO deletes it first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )

    # AppConfig experiments require the flag to already be deployed to the
    # environment before a run can be started (experimentation prerequisites).
    # Use a custom zero-duration/zero-bake strategy (rather than the predefined
    # AppConfig.AllAtOnce, which carries a 10-minute CloudWatch bake window) so
    # the deployment reaches COMPLETE quickly.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number)

    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id}


def _treatment(weight, enabled=True):
    return {"Weight": weight, "FlagValue": {"Enabled": enabled}}


def _create_experiment_definition(ctx, base, flag_key, name=None):
    appconfig = ctx.client("appconfig")
    return appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=flag_key,
        AudienceRule="(eq 1 1)",
        Control=_treatment(50.0),
        Treatments=[_treatment(50.0)],
        Tags=_TAGS,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
