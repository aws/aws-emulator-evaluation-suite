"""experiment-run-events-emitted-for-lifecycle-transitions."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-run-events-emitted-for-lifecycle-transitions"
GROUP = "server-side"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun appends a RUN_STARTED event and StopExperimentRun a RUN_STOPPED
    event to the run's event log as a side effect: there is no API to write run events."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    def_id = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = run_resp["Run"]
    ctx.on_cleanup(lambda: _safe_stop_experiment_run(ctx, app_id, def_id, run_number))

    after_start = appconfig.list_experiment_run_events(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )["Items"]
    assert len(after_start) == 1, f"expected exactly 1 event after start, got {len(after_start)}"
    assert after_start[0]["EventType"] == "RUN_STARTED", (
        f"expected EventType 'RUN_STARTED', got {after_start[0]['EventType']!r}"
    )
    assert after_start[0].get("Description"), "auto-emitted RUN_STARTED event must have a description"
    assert "OccurredAt" in after_start[0], f"RUN_STARTED event missing OccurredAt: {after_start[0]!r}"

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )

    after_stop = appconfig.list_experiment_run_events(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )["Items"]
    assert len(after_stop) == 2, f"expected exactly 2 events after stop, got {len(after_stop)}"
    event_types = {item["EventType"] for item in after_stop}
    assert event_types == {"RUN_STARTED", "RUN_STOPPED"}, (
        f"expected RUN_STARTED and RUN_STOPPED events, got {event_types}"
    )
    stopped = next(item for item in after_stop if item["EventType"] == "RUN_STOPPED")
    assert stopped.get("Description"), "auto-emitted RUN_STOPPED event must have a description"


# ===== helpers =====

def _flag_key() -> str:
    return "flag" + uuid.uuid4().hex[:10]


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags={"sim2real-behav-check": CHECK}
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-"),
        Tags={"sim2real-behav-check": CHECK},
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str):
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags={"sim2real-behav-check": CHECK},
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
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
    # DeleteConfigurationProfile is refused while a hosted version exists: LIFO deletes it first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version["VersionNumber"]
        )
    )
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id: str, env_id: str, profile_id: str, version_number) -> int:
    """AppConfig requires an existing, completed deployment for a configuration profile
    before an experiment run can be started against the feature flag it stores."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real-behav-check": CHECK},
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
    assert completed["State"] == "COMPLETE", f"expected deployment State 'COMPLETE', got {completed['State']!r}"
    return deployment_number


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key) -> str:
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags={"sim2real-behav-check": CHECK},
    )
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, def_id))
    return def_id


def _safe_stop_experiment_run(ctx, app_id: str, def_id: str, run_number: int) -> None:
    """Stop the run only while it is RUNNING: a stop of a DONE run is rejected."""
    appconfig = ctx.client("appconfig")
    try:
        current = appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )
        if current.get("Status") == "RUNNING":
            appconfig.stop_experiment_run(
                ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
            )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
