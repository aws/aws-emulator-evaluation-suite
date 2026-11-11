"""experiment-run-events-ordering."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-events-ordering"
GROUP = "ordering"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentRunEvents returns lifecycle events in strict chronological order, no dup/reorder."""
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
    # OccurredAt has whole-second resolution at best: events a second apart order by time, not by
    # the target's tie-break.
    time.sleep(1.1)
    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )

    # Events may be recorded asynchronously: read until both lifecycle events are listed.
    deadline = time.monotonic() + 30.0
    while True:
        events = appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )["Items"]
        types = {e["EventType"] for e in events}
        if {"RUN_STARTED", "RUN_STOPPED"} <= types or time.monotonic() >= deadline:
            break
        time.sleep(1.0)

    started_events = [e for e in events if e["EventType"] == "RUN_STARTED"]
    stopped_events = [e for e in events if e["EventType"] == "RUN_STOPPED"]
    assert len(started_events) == 1, f"expected exactly one RUN_STARTED, got {len(started_events)}"
    assert len(stopped_events) == 1, f"expected exactly one RUN_STOPPED, got {len(stopped_events)}"

    # AppConfig returns experiment run events most-recent-first (the same convention
    # documented for deployment events), never ascending -- confirmed against real AWS.
    occurred_ats = [e["OccurredAt"] for e in events]
    assert occurred_ats == sorted(occurred_ats, reverse=True), (
        f"events not returned newest-first (descending OccurredAt): expected "
        f"{sorted(occurred_ats, reverse=True)}, got {occurred_ats}"
    )

    start_index = events.index(started_events[0])
    stop_index = events.index(stopped_events[0])
    assert start_index > stop_index, (
        f"RUN_STARTED must appear after RUN_STOPPED in the newest-first list "
        f"(expected start_index > stop_index, got start_index={start_index}, stop_index={stop_index})"
    )


def _ignore_not_found_version(fn):
    """Teardown: a hosted configuration version already gone is fine; every other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        fn()
        return None
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"]


def _safe_delete_definition(appconfig, app_id, def_id):
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    resource_tags = {"sim2real-behav-check": CHECK}
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=resource_tags
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=resource_tags,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
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
    # The profile delete refuses while a hosted version remains; LIFO teardown deletes it first.
    ctx.on_cleanup(lambda: _ignore_not_found_version(lambda: appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number)))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=resource_tags
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
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
        Tags=resource_tags,
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
        Tags={"sim2real-behav-check": CHECK},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
