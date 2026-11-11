"""get-experiment-run-nonexistent-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "get-experiment-run-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-experiment-run-nonexistent"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExperimentRun for a run number that was never started returns
    ResourceNotFoundException rather than an empty/default run object, while fetching
    a run that really was started succeeds and reflects its actual state."""
    appconfig = ctx.client("appconfig")
    prereqs = _create_feature_flag_app(ctx)
    _deploy_feature_flag(ctx, prereqs)
    name = ctx.unique_name("sim2real-behav-expdef-")
    definition = _create_experiment_definition(ctx, prereqs, name)
    exp_id = definition["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_experiment_definition(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=exp_id,
                DeleteType="DESTROY",
            )
        )
    )

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        ExposurePercentage=10.0,
    )
    run_number = run_resp["Run"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.stop_experiment_run(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=exp_id,
                Run=run_number,
            )
        )
    )

    never_started = run_number + 999
    code, code_msg = _error(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=prereqs["app_id"],
            ExperimentDefinitionIdentifier=exp_id,
            Run=never_started,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a run number that was never started, got {code!r}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Experiment run with Experiment Definition Id {exp_id}, Application Id {prereqs['app_id']}, "
        f"and Experiment Run {never_started} could not be found for account {account}."
    ), f"unexpected message: {code_msg!r}"

    # effect absent: the bad Get did not fabricate/list a run for that run number
    runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    listed_runs = [item["Run"] for item in runs["Items"]]
    assert never_started not in listed_runs, (
        f"run {never_started} should not appear in ListExperimentRuns, got {listed_runs}"
    )

    # positive control: fetching the real run succeeds and reflects its actual state
    fetched = appconfig.get_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run_number,
    )
    assert fetched["Run"] == run_number, f"expected Run={run_number}, got {fetched['Run']!r}"
    assert fetched["Status"] == "RUNNING", f"expected Status=RUNNING, got {fetched['Status']!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_cleanup(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_feature_flag_app(ctx) -> dict[str, Any]:
    """Create an Application with a feature-flag ConfigurationProfile + hosted
    configuration version + Environment, wired for experiments."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        )
    )

    flag_key = ctx.unique_name("flag-").replace("_", "-")
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
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=profile_id,
                VersionNumber=version_number,
            )
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        )
    )

    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id, "flag_key": flag_key}


def _deploy_feature_flag(ctx, prereqs: dict[str, Any]) -> None:
    """StartExperimentRun requires an existing (completed) deployment of the
    configuration profile to the environment -- deploy the hosted version created by
    _create_feature_flag_app and wait for the environment to settle."""
    import time

    appconfig = ctx.client("appconfig")
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
        lambda: _safe_cleanup(
            lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
        )
    )
    appconfig.start_deployment(
        ApplicationId=prereqs["app_id"],
        EnvironmentId=prereqs["env_id"],
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=prereqs["profile_id"],
        ConfigurationVersion="1",
    )
    deadline = time.monotonic() + 60.0
    state = None
    while time.monotonic() < deadline:
        state = appconfig.get_environment(
            ApplicationId=prereqs["app_id"], EnvironmentId=prereqs["env_id"]
        )["State"]
        if state == "ReadyForDeployment":
            return
        time.sleep(2.0)
    raise AssertionError(f"environment did not settle after deployment; last state={state!r}")


def _create_experiment_definition(ctx, prereqs: dict[str, Any], name: str) -> dict[str, Any]:
    appconfig = ctx.client("appconfig")
    return appconfig.create_experiment_definition(
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
