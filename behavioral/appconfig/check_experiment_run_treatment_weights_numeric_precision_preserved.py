"""experiment-run-treatment-weights-numeric-precision-preserved."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-treatment-weights-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-treatment-weights-numeric-precision-preserved"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fractional weights (12.5 / 46.25 / 41.25) come back exact, without rounding, from
    Create/GetExperimentDefinition and from a started run's ExperimentDefinitionSnapshot.
    """
    appconfig = ctx.client("appconfig")
    flag_key = f"flag{uuid.uuid4().hex[:10]}"
    app_id, env_id, profile_id = _setup_feature_flag_app(ctx, appconfig, flag_key)

    control_weight = 12.5
    treatment_a_weight = 46.25
    treatment_b_weight = 41.25

    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-behav-expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[
            {"Weight": treatment_a_weight, "FlagValue": {"Enabled": True}},
            {"Weight": treatment_b_weight, "FlagValue": {"Enabled": True}},
        ],
        Control={"Weight": control_weight, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def_id = definition["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    )

    assert definition["Control"]["Weight"] == control_weight, (
        f"control weight on create: expected {control_weight!r} got {definition['Control']['Weight']!r}"
    )
    created_treatment_weights = [t["Weight"] for t in definition["Treatments"]]
    assert created_treatment_weights == [treatment_a_weight, treatment_b_weight], (
        f"treatment weights on create: expected {[treatment_a_weight, treatment_b_weight]!r} "
        f"got {created_treatment_weights!r}"
    )

    fetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert fetched["Control"]["Weight"] == control_weight, (
        f"control weight on get: expected {control_weight!r} got {fetched['Control']['Weight']!r}"
    )
    fetched_treatment_weights = [t["Weight"] for t in fetched["Treatments"]]
    assert fetched_treatment_weights == [treatment_a_weight, treatment_b_weight], (
        f"treatment weights on get: expected {[treatment_a_weight, treatment_b_weight]!r} "
        f"got {fetched_treatment_weights!r}"
    )

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = started["Run"]
    ctx.on_cleanup(lambda: _stop_run_if_running(ctx, app_id, def_id, run_number))

    run_details = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    snapshot = run_details["ExperimentDefinitionSnapshot"]
    assert snapshot["Control"]["Weight"] == control_weight, (
        f"control weight in run snapshot: expected {control_weight!r} got {snapshot['Control']['Weight']!r}"
    )
    snapshot_treatment_weights = [t["Weight"] for t in snapshot["Treatments"]]
    assert snapshot_treatment_weights == [treatment_a_weight, treatment_b_weight], (
        f"treatment weights in run snapshot: expected {[treatment_a_weight, treatment_b_weight]!r} "
        f"got {snapshot_treatment_weights!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
