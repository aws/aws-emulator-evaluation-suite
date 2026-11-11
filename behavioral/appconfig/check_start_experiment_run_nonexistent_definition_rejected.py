"""start-experiment-run-nonexistent-definition-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "start-experiment-run-nonexistent-definition-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun against a non-existent experiment definition id returns
    ResourceNotFoundException without creating a run, while a subsequent call against
    the real definition succeeds and flips its Status IDLE -> ACTIVE."""
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

    bogus_id = "zz" + exp_id[::-1] + "nf"
    err = _error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=prereqs["app_id"],
            ExperimentDefinitionIdentifier=bogus_id,
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent definition id, got {err!r}"
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = (
        f"Experiment Definition with Application Identifier {prereqs['app_id']} and Experiment "
        f"Definition Identifier {bogus_id} could not be found for account {account_id}."
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: the real definition was untouched by the failed call
    still_idle = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert still_idle["Status"] == "IDLE", (
        f"expected the real definition to remain IDLE after the rejected call, "
        f"got {still_idle['Status']!r}"
    )

    # positive control: starting a run against the real definition succeeds
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
    assert run_resp["Status"] == "RUNNING", (
        f"expected the positive control to start RUNNING, got {run_resp['Status']!r}"
    )

    now_active = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert now_active["Status"] == "ACTIVE", (
        f"expected the definition to flip IDLE -> ACTIVE once a run started, "
        f"got {now_active['Status']!r}"
    )


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


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
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
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
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-")
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
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
