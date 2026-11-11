"""start-experiment-run-conflict-while-already-running."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "start-experiment-run-conflict-while-already-running"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-start-experiment-run-conflict-while-already-running"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With run 1 RUNNING, a second StartExperimentRun raises ConflictException and creates no run
    2; after run 1 stops, the identical call succeeds, so the block was run 1's state.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "expflag"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    exp_id, _ = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    started = appconfig.start_experiment_run(ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)
    run_number = started["Run"]
    ctx.on_cleanup(lambda: _ignore_conflict(lambda: appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)))
    assert started["Status"] == "RUNNING", f"expected Run {run_number} RUNNING after start, got {started['Status']}"

    err = _error(lambda: appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id))
    assert err["Code"] == "ConflictException", f"expected ConflictException for a second concurrent run, got {err}"
    expected_message = (
        f"Experiment definition {exp_id} already has a running experiment. "
        "The current experiment run must be stopped before a run can be started."
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    listing = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)["Items"]
    assert len(listing) == 1, f"the rejected StartExperimentRun must not have created a second run: {listing}"
    assert listing[0]["Run"] == run_number, f"expected only Run {run_number} listed, got {listing}"
    assert listing[0]["Status"] == "RUNNING", f"expected Run {run_number} still RUNNING, got {listing[0]}"

    appconfig.stop_experiment_run(ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)

    restarted = appconfig.start_experiment_run(ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)
    second_run_number = restarted["Run"]
    ctx.on_cleanup(lambda: _ignore_conflict(lambda: appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=second_run_number)))
    assert restarted["Status"] == "RUNNING", (
        f"expected the identical StartExperimentRun to succeed once Run {run_number} was stopped, "
        f"got {restarted['Status']}")
    assert second_run_number != run_number, (
        f"restarting must create a new run, not reuse Run {run_number}")

    listing_after_restore = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)["Items"]
    by_run = {r["Run"]: r["Status"] for r in listing_after_restore}
    assert by_run.get(run_number) == "DONE", f"expected Run {run_number} DONE (stopped), got {by_run}"
    assert by_run.get(second_run_number) == "RUNNING", f"expected Run {second_run_number} RUNNING, got {by_run}"


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


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
        # A run that is already stopped refuses a second stop with BadRequestException.
        if e.response["Error"]["Code"] not in ("BadRequestException", "ConflictException", "ResourceNotFoundException"):
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS)["Id"]
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
        Tags=_TAGS,
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
    # DeleteConfigurationProfile is refused while a hosted version survives; LIFO runs this first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
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
        Tags=_TAGS,
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
        Tags=_TAGS,
    )
    exp_id = resp["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY")))
    return exp_id, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
