"""experiment-run-events-chronological-ordering."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-run-events-chronological-ordering"
GROUP = "ordering"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentRunEvents returns start/exposure-update/stop events, most-recent first."""
    appconfig = ctx.client("appconfig")
    env = _create_experiment_ready_env(ctx)
    exp = _create_experiment_definition(ctx, env)
    exp_id = exp["Id"]

    started = _start_experiment_run(ctx, env["app_id"], exp_id, 5.0)
    run_number = started["Run"]

    # OccurredAt has whole-second resolution at best: events a second apart order by time, not by
    # the target's tie-break.
    time.sleep(1.1)
    appconfig.update_experiment_run(
        ApplicationIdentifier=env["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run_number,
        ExposurePercentage=25.0,
    )
    time.sleep(1.1)
    appconfig.stop_experiment_run(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )

    events = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )["Items"],
        lambda items: len(items) >= 3,
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert len(events) >= 3, f"expected at least 3 lifecycle events, got {len(events)}"

    # AppConfig returns experiment run events most-recent-first (the same convention
    # documented for deployment events: "The most recent events are displayed
    # first"), not in ascending chronological order.
    event_types = [item["EventType"] for item in events]
    assert event_types[0] == "RUN_STOPPED", f"first event should be RUN_STOPPED, got {event_types}"
    assert "EXPOSURE_UPDATED" in event_types, f"expected EXPOSURE_UPDATED among events, got {event_types}"
    assert event_types[-1] == "RUN_STARTED", f"last event should be RUN_STARTED, got {event_types}"

    timestamps = [item["OccurredAt"] for item in events]
    assert timestamps == sorted(timestamps, reverse=True), (
        f"events are not in descending (most-recent-first) order: {timestamps}"
    )

    started_idx = event_types.index("RUN_STARTED")
    stopped_idx = event_types.index("RUN_STOPPED")
    exposure_idx = event_types.index("EXPOSURE_UPDATED")
    assert stopped_idx < exposure_idx < started_idx


def _ignore_not_found_version(fn):
    """Teardown: a hosted configuration version already gone is fine; every other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={result!r}")
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
    # The profile delete refuses while a hosted version remains; LIFO teardown deletes it first.
    ctx.on_cleanup(lambda: _ignore_not_found_version(lambda: appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number)))

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
    # Confirmed against real AWS: the two enums do not share a casing convention.
    # DeploymentState comes back SCREAMING_SNAKE_CASE ("COMPLETE"), matching the
    # documented enum, while EnvironmentState comes back PascalCase
    # ("ReadyForDeployment") despite the docs showing READY_FOR_DEPLOYMENT.
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment["DeploymentNumber"]
        )["State"],
        lambda state: state == "COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    # The deployment reaching COMPLETE can still lag behind the environment's own
    # State settling back to ready. StartExperimentRun rejects with ConflictException
    # while the environment reports deploying, so wait for it directly here rather
    # than relying solely on the retry loop in _start_experiment_run.
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
