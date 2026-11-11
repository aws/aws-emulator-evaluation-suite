"""update-experiment-run-malformed-input-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-experiment-run-malformed-input-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_FLAG_KEY = "my-feature-flag"
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentRun with an ExposurePercentage outside the documented 0-100 range
    is rejected with BadRequestException before any state change is committed to the run."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_feature_flag_profile(ctx, app_id)
    # StartExperimentRun requires an existing (completed) deployment for the
    # configuration profile that the experiment's flag belongs to.
    _deploy_simple_flag(ctx, appconfig, app_id, env_id, profile_id, _FLAG_KEY)
    exp_id = _create_simple_experiment_definition(ctx, app_id, profile_id, env_id, flag_key=_FLAG_KEY)

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=exp_id,
        ExposurePercentage=25.0,
    )
    run_number = started["Run"]
    ctx.on_cleanup(lambda: _safe_stop_run(appconfig, app_id, exp_id, run_number))
    assert started["ExposurePercentage"] == 25.0, (
        f"expected positive control to start at 25.0, got {started['ExposurePercentage']}"
    )
    updated_at_before = started["UpdatedAt"]

    # Break exactly one thing: an out-of-range exposure percentage (> 100).
    code, message = _error(
        lambda: appconfig.update_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            Run=run_number,
            ExposurePercentage=150.0,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = (
        "1 validation error detected: Value '150.0' at 'exposurePercentage' failed to satisfy "
        "constraint: Member must have value less than or equal to 100.0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the run's exposure percentage and update timestamp are unchanged.
    still = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert still["ExposurePercentage"] == 25.0, "exposure percentage mutated despite rejection"
    assert still["UpdatedAt"] == updated_at_before, "run was updated despite rejected request"

    # Positive control: a valid in-range exposure percentage is accepted in the same file.
    updated = appconfig.update_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=exp_id,
        Run=run_number,
        ExposurePercentage=60.0,
    )
    assert updated["ExposurePercentage"] == 60.0, (
        f"expected restore update to report 60.0, got {updated['ExposurePercentage']}"
    )
    confirmed = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert confirmed["ExposurePercentage"] == 60.0, (
        f"expected independent read to reflect 60.0 after valid update, got {confirmed['ExposurePercentage']}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_stop_run(appconfig, app_id, exp_id, run_number):
    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_version_if_present(appconfig, app_id, profile_id, version):
    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="BYPASS",
        )
    )
    return profile_id


def _deploy_simple_flag(ctx, appconfig, app_id, env_id, profile_id, flag_key, timeout_s=180.0):
    """Deploy a simple feature flag and wait for the deployment to finish.

    StartExperimentRun requires both that a deployment exists for the configuration
    profile AND that the environment is not currently mid-deployment (ConflictException:
    "Environment ... currently has a state of DEPLOYING"). The predefined
    "AppConfig.AllAtOnce" strategy carries a 10-minute CloudWatch-alarm bake time, so we
    use a custom strategy with zero deployment duration and zero final bake time to
    finish quickly instead.
    """
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(lambda: _delete_version_if_present(appconfig, app_id, profile_id, version))
    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version),
    )
    deployment_number = deployment["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        resp = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        state = resp["State"]
        if state == "COMPLETE":
            return
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment {deployment_number} failed with state={state}")
        time.sleep(2)
    raise AssertionError(
        f"deployment {deployment_number} never reached COMPLETE (last state={state})"
    )



def _create_simple_experiment_definition(
    ctx, app_id, profile_id, env_id, flag_key="my-feature-flag", name=None
):
    appconfig = ctx.client("appconfig")
    exp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    exp_id = exp["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            DeleteType="DESTROY",
        )
    )
    return exp_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
