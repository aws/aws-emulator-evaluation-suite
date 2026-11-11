"""stop-experiment-run-not-started-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-experiment-run-not-started-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopExperimentRun on an already-DONE run raises BadRequestException (not ConflictException)
    and leaves the run's terminal state untouched.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = f"flag{uuid.uuid4().hex[:8]}"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    def_id = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = started["Run"]

    # positive control: the first stop on a RUNNING run succeeds
    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        Run=run_number,
    )
    assert stopped["Status"] == "DONE", f"expected the positive-control stop to reach DONE, got {stopped['Status']!r}"
    ended_at_first = stopped["EndedAt"]

    # negative: stopping the same, already-DONE run again is rejected
    err = _error(
        lambda: appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException for a stop on an already-DONE run, got {err}"
    expected_message = f"Experiment run {run_number} for experiment definition {def_id} is not running."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: the run's terminal state was not touched by the rejected second stop
    after = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert after["Status"] == "DONE", f"rejected second stop must leave Status as DONE, got {after['Status']!r}"
    assert after["EndedAt"] == ended_at_first, (
        f"rejected second stop must not move EndedAt: expected {ended_at_first!r}, got {after['EndedAt']!r}"
    )


_PREFIX = "sim2real-appconfig-"


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected StopExperimentRun on a DONE run to be rejected, but it SUCCEEDED: {result!r}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name(_PREFIX + "app-"), Tags=_TAGS)["Id"]

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
        ApplicationId=app_id, Name=ctx.unique_name(_PREFIX + "env-"), Tags=_TAGS
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
        Tags=_TAGS,
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
        Tags=_TAGS,
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
        Tags=_TAGS,
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
