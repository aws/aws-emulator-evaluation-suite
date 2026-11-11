"""experiment-run-full-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "experiment-run-full-lifecycle"
GROUP = "experiment"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun makes a run RUNNING, UpdateExperimentRun changes metadata visible on the
    next Get, and StopExperimentRun makes it DONE, with ListExperimentRuns reflecting every step.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "expflag"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    exp_id, _ = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, ExposurePercentage=50.0)
    run_number = started["Run"]
    ctx.on_cleanup(lambda: _ignore_conflict(lambda: appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)))
    assert run_number == 1, f"expected the first run on a fresh experiment definition to be Run 1, got {run_number}"
    assert started["Status"] == "RUNNING", f"expected RUNNING immediately after start, got {started['Status']}"

    got = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)
    assert got["Status"] == "RUNNING", f"expected GetExperimentRun to reflect RUNNING, got {got['Status']}"

    updated = appconfig.update_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number,
        Description="mid-run note",
    )
    assert updated["Description"] == "mid-run note", (
        f"expected UpdateExperimentRun to echo the new Description, got {updated['Description']!r}")

    got2 = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)
    assert got2["Description"] == "mid-run note", "UpdateExperimentRun not reflected in Get"

    running_listing = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)["Items"]
    running_entry = next(item for item in running_listing if item["Run"] == run_number)
    assert running_entry["Status"] == "RUNNING", (
        f"expected ListExperimentRuns to show RUNNING, got {running_entry['Status']}")

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)
    assert stopped["Status"] == "DONE", f"expected DONE after stop, got {stopped['Status']}"

    done_listing = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)["Items"]
    done_entry = next(item for item in done_listing if item["Run"] == run_number)
    assert done_entry["Status"] == "DONE", (
        f"expected ListExperimentRuns to show DONE after stop, got {done_entry['Status']}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ignore_conflict(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"))["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_environment(
        ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS")))
    return env_id


def _create_feature_flag_profile(ctx, app_id, flag_key):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS")))
    content = json.dumps({
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
        "version": "1",
    }).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=content, ContentType="application/json",
    )["VersionNumber"]
    return profile_id, version_number


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_no_bake_deployment_strategy(ctx):
    """A custom zero-duration, zero-bake strategy avoids AppConfig.AllAtOnce's ~10min

    FinalBakeTimeInMinutes, which would otherwise blow past the check's overall timeout
    just waiting for a prerequisite deployment to leave the BAKING state.
    """
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)))
    return strategy_id


def _deploy_configuration(ctx, app_id, env_id, profile_id, version_number):
    """AppConfig requires an existing (completed) deployment before an experiment run can start."""
    appconfig = ctx.client("appconfig")
    strategy_id = _create_no_bake_deployment_strategy(ctx)
    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = deployment["DeploymentNumber"]
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number),
        lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK", "REVERTED"),
        timeout_s=90.0,
        interval_s=3.0,
    )


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key,
                                   control_weight=50.0, treatment_weight=50.0):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": control_weight},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": treatment_weight}],
    )
    exp_id = resp["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY")))
    return exp_id, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
