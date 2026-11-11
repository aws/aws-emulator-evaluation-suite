"""experiment-run-metrics-computed-server-side."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "experiment-run-metrics-computed-server-side"
GROUP = "server-side"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExperimentRun's StartedAt/EndedAt/Status and the ListExperimentRunEvents timeline are set
    by the service on start and stop, never supplied by the caller, and appear in the expected
    order.
    """
    appconfig = ctx.client("appconfig")

    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "metricflag"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)

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
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number)

    exp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": 50},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": 50}],
    )
    exp_id = exp["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    )

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, ExposurePercentage=50
    )
    run_number = started["Run"]
    ctx.on_cleanup(
        lambda: appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    )

    fetched = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert fetched["Status"] == "RUNNING", f"expected RUNNING right after start, got {fetched['Status']!r}"
    started_at = fetched["StartedAt"]
    assert started_at is not None, "StartedAt was not populated by the service after starting the run"
    assert fetched.get("EndedAt") is None, "a freshly started run should have no EndedAt yet"

    events_after_start = appconfig.list_experiment_run_events(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )["Items"]
    start_events = [e for e in events_after_start if e["EventType"] == "RUN_STARTED"]
    assert len(start_events) == 1, f"expected exactly one RUN_STARTED event, got {len(start_events)}"
    assert start_events[0]["OccurredAt"] is not None, "RUN_STARTED event has no server-stamped OccurredAt"

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )

    def _probe():
        return appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )

    done = _poll_until(_probe, lambda r: r["Status"] == "DONE", timeout_s=30.0)
    ended_at = done["EndedAt"]
    assert ended_at is not None, "EndedAt was not populated by the service after stopping the run"
    assert ended_at >= started_at, "EndedAt precedes StartedAt -- timestamps are not server-computed correctly"

    events_after_stop = appconfig.list_experiment_run_events(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )["Items"]
    stop_events = [e for e in events_after_stop if e["EventType"] == "RUN_STOPPED"]
    assert len(stop_events) == 1, f"expected exactly one RUN_STOPPED event, got {len(stop_events)}"
    assert stop_events[0]["OccurredAt"] is not None, "RUN_STOPPED event has no server-stamped OccurredAt"
    assert len(events_after_stop) > len(events_after_start), (
        "no new event was recorded server-side as a result of StopExperimentRun"
    )


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
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout}s (last state {last_state})")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"))
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str) -> tuple[str, int]:
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-ffprofile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    content = json.dumps(
        {
            "version": "1",
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    version_number = version["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
    return profile_id, version_number


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
