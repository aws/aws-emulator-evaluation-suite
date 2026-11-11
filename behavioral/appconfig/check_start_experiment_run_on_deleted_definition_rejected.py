"""start-experiment-run-on-deleted-definition-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-run-on-deleted-definition-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun against a permanently deleted experiment definition is rejected
    with ResourceNotFoundException, and no run object is created for it."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = f"flag{uuid.uuid4().hex[:8]}"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)

    deleted_def_id = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)
    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=deleted_def_id,
        DeleteType="DESTROY",
    )

    err = _error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=deleted_def_id
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {deleted_def_id} could not be found for account {account_id}."
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: no run was created against the deleted definition
    err_get_run = _error(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=deleted_def_id,
            Run=1,
        )
    )
    assert err_get_run["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a run on the deleted definition, "
        f"got {err_get_run}"
    )
    # GetExperimentRun reports the missing definition, not the run, with the same message.
    expected_get_run_message = expected_message
    assert err_get_run["Message"] == expected_get_run_message, (
        f"expected message {expected_get_run_message!r}, got {err_get_run['Message']!r}"
    )

    # positive control: a live definition in the same application starts a run fine
    live_def_id = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)
    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=live_def_id
    )
    assert started["Status"] == "RUNNING", f"expected RUNNING, got {started['Status']}"
    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=live_def_id,
        Run=started["Run"],
    )

    # terminal read: independent get_experiment_run, not the start call's own response
    got_run = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=live_def_id,
        Run=started["Run"],
    )
    assert got_run["Status"] == "DONE", (
        f"expected an independent read to show the stopped run as DONE, got {got_run['Status']}"
    )


_PREFIX = "sim2real-appconfig-"


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name(_PREFIX + "app-"))["Id"]

    def _cleanup():
        try:
            appconfig.delete_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name(_PREFIX + "env-")
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return env_id


def _create_feature_flag_profile(ctx, app_id, flag_key):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name(_PREFIX + "profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

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
    # DeleteConfigurationProfile is refused while a hosted version survives; LIFO runs this first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version["VersionNumber"]
        )
    )
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id, env_id, profile_id, version_number):
    """AppConfig requires an existing, completed deployment for a configuration profile
    before an experiment run can be started against the feature flag it stores."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name(_PREFIX + "depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )
    strategy_id = strategy["Id"]

    def _cleanup_strategy():
        try:
            appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_strategy)

    dep = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = dep["DeploymentNumber"]

    deadline = time.monotonic() + 30.0
    last_state = None
    while time.monotonic() < deadline:
        got = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        last_state = got["State"]
        if last_state == "COMPLETE":
            return deployment_number
        time.sleep(1.5)
    raise AssertionError(f"deployment did not COMPLETE within 30s; last state={last_state!r}")


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name(_PREFIX + "expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
    )
    def_id = resp["Id"]

    def _cleanup():
        try:
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=app_id,
                ExperimentDefinitionIdentifier=def_id,
                DeleteType="DESTROY",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return def_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
