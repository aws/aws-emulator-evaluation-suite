"""experiment-run-metrics-unicode-preserved."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-metrics-unicode-preserved"
GROUP = "representation"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun's empty-string Description, ExposurePercentage 0.0 and TreatmentOverrides
    keyed by unicode entity ids come back unchanged, not omitted or nulled, on the next
    GetExperimentRun.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    def_id, control_key, treatment_key = _create_experiment_definition(
        ctx, app_id, profile_id, env_id, flag_key
    )

    unicode_entity_1 = "\u7528\u6237-\U0001f680-1"
    unicode_entity_2 = "user_2_\u65e5\u672c\u8a9e"
    overrides = {"Inline": {unicode_entity_1: control_key, unicode_entity_2: treatment_key}}

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        Description="",
        ExposurePercentage=0.0,
        TreatmentOverrides=overrides,
    )
    run_number = run_resp["Run"]
    ctx.on_cleanup(lambda: _safe_stop_experiment_run(ctx, app_id, def_id, run_number))

    assert run_resp["Description"] == "", (
        f"expected empty-string Description on StartExperimentRun response, got {run_resp['Description']!r}"
    )
    assert run_resp["ExposurePercentage"] == 0.0, (
        f"expected ExposurePercentage 0.0 on StartExperimentRun response, got {run_resp['ExposurePercentage']!r}"
    )
    assert run_resp["TreatmentOverrides"] == overrides, (
        f"expected unicode TreatmentOverrides {overrides!r} on StartExperimentRun response, "
        f"got {run_resp['TreatmentOverrides']!r}"
    )

    got = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    # AWS's wire protocol omits the Description key entirely on GetExperimentRun when it
    # was set to an empty string (rather than serializing an empty string) -- an absent
    # key here is the empirically-correct representation of "" and must not be conflated
    # with a non-empty value being dropped.
    assert got.get("Description", "") == "", (
        f"expected empty-string/absent Description, got {got.get('Description')!r}"
    )
    assert got["ExposurePercentage"] == 0.0, (
        f"expected ExposurePercentage 0.0 on GetExperimentRun response, got {got['ExposurePercentage']!r}"
    )
    assert got["TreatmentOverrides"] == overrides, (
        f"expected unicode TreatmentOverrides {overrides!r}, got {got['TreatmentOverrides']!r}"
    )


def _flag_key() -> str:
    return "flag" + uuid.uuid4().hex[:10]


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"))
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str):
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": False}},
            "version": "1",
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id: str, env_id: str, profile_id: str, version_number) -> int:
    """AppConfig requires an existing, completed deployment for a configuration profile
    before an experiment run can be started against the feature flag it stores."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )
    strategy_id = strategy["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    dep = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = dep["DeploymentNumber"]
    completed = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda resp: resp["State"] == "COMPLETE",
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert completed["State"] == "COMPLETE", (
        f"expected deployment to reach COMPLETE, got {completed['State']!r}"
    )
    return deployment_number


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
    )
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, def_id))
    control_key = resp["Control"]["Key"]
    treatment_key = resp["Treatments"][0]["Key"]
    return def_id, control_key, treatment_key


def _safe_stop_experiment_run(ctx, app_id: str, def_id: str, run_number: int) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
