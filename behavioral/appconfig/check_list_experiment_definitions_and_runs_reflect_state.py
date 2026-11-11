"""list-experiment-definitions-and-runs-reflect-state."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-experiment-definitions-and-runs-reflect-state"
GROUP = "data-plane"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-list-reflects-state"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentDefinitions and ListExperimentRuns surface a newly created
    definition/run and its current status immediately after each mutation, not a
    stale/cached snapshot."""
    appconfig = ctx.client("appconfig")
    prereqs = _setup_experiment_prereqs(ctx)

    definition = _create_experiment_definition(ctx, prereqs)
    exp_id = definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment(appconfig, prereqs["app_id"], exp_id))

    defs_after_create = appconfig.list_experiment_definitions(ApplicationIdentifier=prereqs["app_id"])["Items"]
    matching = [d for d in defs_after_create if d["Id"] == exp_id]
    assert len(matching) == 1, f"expected exactly 1 definition {exp_id!r} in list, got {matching!r}"
    assert matching[0]["Status"] == "IDLE", f"expected freshly created definition Status=IDLE, got {matching[0]['Status']!r}"

    runs_before_start = appconfig.list_experiment_runs(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )["Items"]
    assert runs_before_start == [], f"expected no runs before start_experiment_run, got {runs_before_start!r}"

    start_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    run_number = start_resp["Run"]
    ctx.on_cleanup(lambda: _safe_stop_run(appconfig, prereqs["app_id"], exp_id, run_number))

    runs_after_start = appconfig.list_experiment_runs(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )["Items"]
    matching_run = [r for r in runs_after_start if r["Run"] == run_number]
    assert len(matching_run) == 1, f"expected exactly 1 run {run_number!r} in list, got {matching_run!r}"
    assert matching_run[0]["Status"] == "RUNNING", f"expected started run Status=RUNNING, got {matching_run[0]['Status']!r}"

    defs_while_running = appconfig.list_experiment_definitions(ApplicationIdentifier=prereqs["app_id"])["Items"]
    matching_def_running = [d for d in defs_while_running if d["Id"] == exp_id]
    assert len(matching_def_running) == 1, f"expected exactly 1 definition {exp_id!r} in list, got {matching_def_running!r}"
    assert matching_def_running[0]["Status"] == "ACTIVE", (
        f"expected definition Status=ACTIVE while its run is RUNNING, got {matching_def_running[0]['Status']!r}"
    )

    appconfig.stop_experiment_run(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )

    runs_after_stop = appconfig.list_experiment_runs(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )["Items"]
    matching_run_stopped = [r for r in runs_after_stop if r["Run"] == run_number]
    assert len(matching_run_stopped) == 1, f"expected exactly 1 run {run_number!r} in list, got {matching_run_stopped!r}"
    assert matching_run_stopped[0]["Status"] == "DONE", f"expected stopped run Status=DONE, got {matching_run_stopped[0]['Status']!r}"


def _make_flag_content(flag_key: str) -> bytes:
    return json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")


def _setup_experiment_prereqs(ctx, flag_key: str = "expflag") -> dict[str, str]:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-appcfg-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-appcfg-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )

    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=_make_flag_content(flag_key),
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    # StartExperimentRun requires an existing deployment of the configuration
    # profile to the environment. Deploy it now via a zero-duration/zero-bake
    # custom strategy so it reaches COMPLETE almost immediately.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-appcfg-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        ReplicateTo="NONE",
        FinalBakeTimeInMinutes=0,
        Tags=_TAGS,
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

    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _wait_for_deployment_complete(
    appconfig, app_id: str, env_id: str, deployment_number: int, *, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if last["State"] == "COMPLETE":
            return last
        if last["State"] in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state: {last!r}")
        time.sleep(interval_s)
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s (last={last!r})")


def _create_experiment_definition(ctx, prereqs: dict[str, str], name: str | None = None, **overrides: Any) -> dict[str, Any]:
    appconfig = ctx.client("appconfig")
    name = name or ctx.unique_name("sim2real-appcfg-exp-")
    params: dict[str, Any] = dict(
        ApplicationIdentifier=prereqs["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=prereqs["profile_id"],
        EnvironmentIdentifier=prereqs["env_id"],
        FlagKey=prereqs["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    params.update(overrides)
    return appconfig.create_experiment_definition(**params)


def _safe_delete_experiment(appconfig, app_id: str, exp_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_stop_run(appconfig, app_id: str, exp_id: str, run_number: int) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
