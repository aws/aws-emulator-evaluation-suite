"""list-experiment-run-events-nonexistent-run-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-experiment-run-events-nonexistent-run-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_FLAG_KEY = "my-feature-flag"
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-experiment-run-events-nonexistent-run"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListExperimentRunEvents under an experiment definition that never existed raises
    ResourceNotFoundException rather than returning an empty list.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_feature_flag_profile(ctx, app_id)
    _deploy_simple_flag(ctx, appconfig, app_id, env_id, profile_id, _FLAG_KEY)
    exp_id = _create_simple_experiment_definition(ctx, app_id, profile_id, env_id, flag_key=_FLAG_KEY)

    bogus_exp_id = "nonexistent-experiment-def"
    err = _error(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=bogus_exp_id,
            Run=1,
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {bogus_exp_id} could not be found for account {account}."
    ), f"unexpected message: {err['Message']!r}"

    # Positive control: a real, started run under the real experiment definition resolves
    # and lists events without error.
    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    run_number = run_resp["Run"]
    ctx.on_cleanup(lambda: _safe_stop_run(appconfig, app_id, exp_id, run_number))
    resp = appconfig.list_experiment_run_events(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    items = resp.get("Items", [])
    event_types = [item["EventType"] for item in items]
    assert "RUN_STARTED" in event_types, (
        f"expected a RUN_STARTED event for the real run, got event types {event_types}"
    )



def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_stop_run(appconfig, app_id, exp_id, run_number):
    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    )
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
