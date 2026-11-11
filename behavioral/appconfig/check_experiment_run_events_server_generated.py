"""experiment-run-events-server-generated."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-events-server-generated"
GROUP = "server-side"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Starting and stopping a run makes ListExperimentRunEvents carry both transitions with server-
    assigned EventType, OccurredAt and TriggeredBy; the service has no API to write events.
    """
    appconfig = ctx.client("appconfig")
    setup = _setup_feature_flag_app(ctx, appconfig)

    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=setup["app_id"],
        Name=ctx.unique_name("sim2real-behav-expdef-"),
        ConfigurationProfileIdentifier=setup["profile_id"],
        EnvironmentIdentifier=setup["env_id"],
        FlagKey=setup["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags={"sim2real-behav-check": CHECK},
    )
    app_id, def_id = setup["app_id"], definition["Id"]

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = started["Run"]
    ctx.on_cleanup(lambda: _stop_run_if_running(ctx, app_id, def_id, run_number))

    events_after_start = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )["Items"],
        lambda items: any(e.get("EventType") == "RUN_STARTED" for e in items),
        timeout_s=30.0,
        interval_s=2.0,
    )
    run_started = next(e for e in events_after_start if e["EventType"] == "RUN_STARTED")
    assert run_started["TriggeredBy"] == "USER", (
        f"expected server-assigned TriggeredBy 'USER' for a directly-started run, "
        f"got {run_started.get('TriggeredBy')!r}"
    )
    assert "OccurredAt" in run_started, f"RUN_STARTED event missing server-assigned OccurredAt: {run_started!r}"

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )

    events_after_stop = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )["Items"],
        lambda items: any(e.get("EventType") == "RUN_STOPPED" for e in items),
        timeout_s=30.0,
        interval_s=2.0,
    )
    run_stopped = next(e for e in events_after_stop if e["EventType"] == "RUN_STOPPED")
    assert run_stopped["TriggeredBy"] == "USER", (
        f"expected server-assigned TriggeredBy 'USER' for a directly-stopped run, "
        f"got {run_stopped.get('TriggeredBy')!r}"
    )
    assert run_stopped["OccurredAt"] >= run_started["OccurredAt"], (
        f"RUN_STOPPED OccurredAt={run_stopped['OccurredAt']!r} must not precede "
        f"RUN_STARTED OccurredAt={run_started['OccurredAt']!r}"
    )


def _setup_feature_flag_app(ctx, appconfig) -> dict:
    flag_key = f"flag{uuid.uuid4().hex[:10]}"
    tags = {"sim2real-behav-check": CHECK}
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=tags)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=tags
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-ff-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=tags,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = json.dumps(
        {"flags": {flag_key: {"name": flag_key}}, "values": {flag_key: {"enabled": True}}, "version": "1"}
    ).encode("utf-8")
    hosted_version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    _deploy_and_wait(ctx, appconfig, app_id, env_id, profile_id, hosted_version["VersionNumber"])
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _deploy_and_wait(ctx, appconfig, app_id, env_id, profile_id, version_number) -> None:
    """StartExperimentRun requires an existing (COMPLETE) deployment for the configuration profile."""
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real-behav-check": CHECK},
    )
    strategy_id = strategy["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
        DeploymentStrategyId=strategy_id,
    )
    deployment_number = deployment["DeploymentNumber"]
    deadline = time.monotonic() + 60.0
    state = deployment.get("State")
    while time.monotonic() < deadline:
        current = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        state = current["State"]
        if state == "COMPLETE":
            return
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered unexpected terminal state: {state}")
        time.sleep(2.0)

    raise AssertionError(f"deployment did not reach BAKING/COMPLETE within 60s; last state: {state}")



def _stop_run_if_running(ctx, app_id, def_id, run_number) -> None:
    appconfig = ctx.client("appconfig")
    try:
        current = appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if current.get("Status") == "RUNNING":
        try:
            appconfig.stop_experiment_run(
                ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
