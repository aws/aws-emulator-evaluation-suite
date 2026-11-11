"""experiment-run-start-while-running-conflict-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-run-start-while-running-conflict-rejected"
GROUP = "server-side"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-conflict"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With run 1 RUNNING, a second StartExperimentRun raises ConflictException and
    ListExperimentRuns still shows one run; after run 1 stops, the same call succeeds and creates
    run 2.
    """
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
    ctx.on_cleanup(lambda: _destroy_definition(appconfig, app_id, def_id))

    first_run = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    first_run_number = first_run["Run"]
    ctx.on_cleanup(lambda: _stop_run_if_running(ctx, app_id, def_id, first_run_number))

    err = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )
    )
    assert err["Code"] == "ConflictException", (
        f"expected ConflictException while run #{first_run_number} is RUNNING, got {err['Code']}"
    )
    conflict = (
        f"Experiment definition {def_id} already has a running experiment. "
        "The current experiment run must be stopped before a run can be started."
    )
    assert err["Message"] == conflict, f"expected message {conflict!r}, got {err['Message']!r}"

    # Effect absent: still exactly one run on this definition.
    runs_after_rejection = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert len(runs_after_rejection) == 1, f"rejected StartExperimentRun must not create a run: {runs_after_rejection}"
    assert runs_after_rejection[0]["Run"] == first_run_number, (
        f"expected only run #{first_run_number} to remain, saw {runs_after_rejection[0]['Run']}"
    )

    # Positive control: stop the running run, then starting a new one succeeds.
    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=first_run_number
    )
    second_run = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    second_run_number = second_run["Run"]
    ctx.on_cleanup(lambda: _stop_run_if_running(ctx, app_id, def_id, second_run_number))
    assert second_run["Status"] == "RUNNING", f"expected RUNNING after restart, got {second_run['Status']}"
    assert second_run_number != first_run_number, "restarted run must get a new run number, not reuse the old one"

    runs_after_control = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert {r["Run"] for r in runs_after_control} == {first_run_number, second_run_number}, (
        f"expected exactly runs {{{first_run_number}, {second_run_number}}}, got {runs_after_control}"
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
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=hosted_version["VersionNumber"]
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


def _destroy_definition(appconfig, app_id, def_id) -> None:
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available and must not be reported as
    an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
