"""experiment-run-events-chronological-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-events-chronological-order"
GROUP = "ordering"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-events-chronological-order"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentRunEvents returns the run's lifecycle events in strictly descending
    (most-recent-first) OccurredAt order, with RUN_STOPPED first and RUN_STARTED last,
    matching the actual start/stop timeline we drove in reverse."""
    appconfig = ctx.client("appconfig")
    base = _setup_experiment_base(ctx)
    created = _create_experiment_definition(ctx, appconfig, base)
    def_id = created["Id"]

    start = appconfig.start_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    run_number = start["Run"]

    # Wait for the RUN_STARTED event to be recorded before stopping.
    _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=base["app_id"],
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )["Items"],
        lambda items: len(items) >= 1,
        timeout_s=30.0,
        interval_s=1.5,
    )

    appconfig.stop_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id, Run=run_number
    )

    events = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=base["app_id"],
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )["Items"],
        lambda items: len(items) >= 2,
        timeout_s=30.0,
        interval_s=1.5,
    )

    occurred_ats = [e["OccurredAt"] for e in events]
    assert occurred_ats == sorted(occurred_ats, reverse=True), (
        f"events not in descending (most-recent-first) order: {events}"
    )

    event_types = [e["EventType"] for e in events]
    assert event_types[0] == "RUN_STOPPED", event_types
    assert event_types[-1] == "RUN_STARTED", event_types


_AUDIENCE_RULE = '(eq $country "US")'


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _setup_experiment_base(ctx, flag_key="expflag1"):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-appcfg-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    content = {
        "version": "1",
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
    }
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
        ContentType="application/json",
    )["VersionNumber"]

    # Experiments require an existing deployment of the flag to the environment. Use a
    # custom zero-bake-time strategy so the deployment reaches COMPLETE quickly instead of
    # sitting in the 10-minute default bake window of the predefined AllAtOnce strategy.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
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
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment["DeploymentNumber"])

    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _wait_for_deployment_complete(
    appconfig, app_id, env_id, deployment_number, timeout_s=240.0, interval_s=5.0
):
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last = None
    while _time.monotonic() < deadline:
        last = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if last["State"] == "COMPLETE":
            return last
        if last["State"] in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment failed: {last}")
        _time.sleep(interval_s)
    raise AssertionError(f"deployment not complete within {timeout_s}s; last={last!r}")


def _create_experiment_definition(ctx, appconfig, base, name=None):
    name = name or ctx.unique_name("sim2real-exp-")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=base["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def_id = resp["Id"]

    def _cleanup():
        try:
            for r in appconfig.list_experiment_runs(
                ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
            ).get("Items", []):
                if r.get("Status") == "RUNNING":
                    try:
                        appconfig.stop_experiment_run(
                            ApplicationIdentifier=base["app_id"],
                            ExperimentDefinitionIdentifier=def_id,
                            Run=r["Run"],
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=base["app_id"],
                ExperimentDefinitionIdentifier=def_id,
                DeleteType="DESTROY",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
