"""experiment-run-treatment-assignment-enforced-serverside."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-treatment-assignment-enforced-serverside"
GROUP = "server-side"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-treatment-assignment"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AppConfig assigns treatment keys ("c", then "t1", "t2", ...) itself, since TreatmentInput has
    no Key; those keys come back from CreateExperimentDefinition and carry over unchanged into a
    started run's ExperimentDefinitionSnapshot.
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
        Treatments=[
            {"Weight": 30.0, "FlagValue": {"Enabled": True}},
            {"Weight": 20.0, "FlagValue": {"Enabled": True, "AttributeValues": {}}},
        ],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
    )
    def_id = definition["Id"]

    # Server assigned the keys; we never supplied any Key in the request.
    assert definition["Control"]["Key"] == "c", (
        f"expected server-assigned control key 'c', got {definition['Control'].get('Key')!r}"
    )
    treatment_keys = [t["Key"] for t in definition["Treatments"]]
    assert treatment_keys == ["t1", "t2"], (
        f"expected server-assigned treatment keys ['t1', 't2'] in declaration order, got {treatment_keys!r}"
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
    assert snapshot["Control"]["Key"] == "c", (
        f"run snapshot must carry forward the server-assigned control key 'c', got {snapshot['Control'].get('Key')!r}"
    )
    snapshot_treatment_keys = [t["Key"] for t in snapshot["Treatments"]]
    assert snapshot_treatment_keys == ["t1", "t2"], (
        f"run snapshot must carry forward the server-assigned treatment keys ['t1', 't2'], got {snapshot_treatment_keys!r}"
    )
    # The snapshot's weights match exactly what was configured server-side.
    assert snapshot["Control"]["Weight"] == 50.0, (
        f"expected control weight 50.0 unchanged in run snapshot, got {snapshot['Control'].get('Weight')!r}"
    )
    snapshot_treatment_weights = [t["Weight"] for t in snapshot["Treatments"]]
    assert snapshot_treatment_weights == [30.0, 20.0], (
        f"expected treatment weights [30.0, 20.0] unchanged in run snapshot, got {snapshot_treatment_weights!r}"
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
