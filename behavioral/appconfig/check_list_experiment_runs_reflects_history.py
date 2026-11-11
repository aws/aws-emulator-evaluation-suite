"""list-experiment-runs-reflects-history."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-experiment-runs-reflects-history"
GROUP = "data-plane"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-experiment-runs-reflects-history"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentRuns returns full run history: both a stopped run and a currently active one."""
    appconfig = ctx.client("appconfig")
    flag_key = f"flag{uuid.uuid4().hex[:10]}"
    app_id, env_id, profile_id = _setup_feature_flag_app(ctx, appconfig, flag_key)

    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-behav-expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def_id = definition["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    )

    first_run = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    first_run_number = first_run["Run"]
    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=first_run_number
    )

    second_run = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    second_run_number = second_run["Run"]
    ctx.on_cleanup(lambda: _stop_run_if_running(ctx, app_id, def_id, second_run_number))

    all_runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )["Items"]
    runs_by_number = {r["Run"]: r for r in all_runs}

    assert set(runs_by_number.keys()) == {first_run_number, second_run_number}, (
        f"expected ListExperimentRuns to return both runs "
        f"{first_run_number!r}/{second_run_number!r}, got {sorted(runs_by_number)!r}"
    )
    assert runs_by_number[first_run_number]["Status"] == "DONE", (
        f"expected stopped run {first_run_number!r} to report Status=DONE, "
        f"got {runs_by_number[first_run_number]['Status']!r}"
    )
    assert runs_by_number[second_run_number]["Status"] == "RUNNING", (
        f"expected still-active run {second_run_number!r} to report Status=RUNNING, "
        f"got {runs_by_number[second_run_number]['Status']!r}"
    )

    running_only = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Status="RUNNING"
    )["Items"]
    assert {r["Run"] for r in running_only} == {second_run_number}, (
        f"Status=RUNNING filter expected to return only {second_run_number!r}, "
        f"got {sorted(r['Run'] for r in running_only)!r}"
    )

    done_only = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Status="DONE"
    )["Items"]
    assert {r["Run"] for r in done_only} == {first_run_number}, (
        f"Status=DONE filter expected to return only {first_run_number!r}, "
        f"got {sorted(r['Run'] for r in done_only)!r}"
    )


def _setup_feature_flag_app(ctx, appconfig, flag_key: str):
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-ff-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
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
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            VersionNumber=hosted_version["VersionNumber"],
        )
    )
    _deploy_and_wait(ctx, appconfig, app_id, env_id, profile_id, hosted_version["VersionNumber"])
    return app_id, env_id, profile_id


def _deploy_and_wait(ctx, appconfig, app_id, env_id, profile_id, version_number) -> None:
    """StartExperimentRun requires an existing (COMPLETE) deployment for the configuration profile."""
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
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
    raise AssertionError(f"deployment did not reach COMPLETE within 60s; last state: {state}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
