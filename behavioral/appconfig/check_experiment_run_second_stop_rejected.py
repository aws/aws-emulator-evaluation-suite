"""experiment-run-second-stop-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-second-stop-rejected"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Stopping an already-terminal (DONE) experiment run a second time is rejected with
    BadRequestException, and the run's terminal state (Status/EndedAt) is left unchanged --
    while the first stop call, which does the identical transition legitimately, succeeds."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    def_id, _created = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = run_resp["Run"]

    _poll_until(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        ),
        lambda resp: resp["Status"] == "RUNNING",
        timeout_s=20.0,
    )

    # Positive control: the first stop legitimately transitions RUNNING -> DONE.
    first_stop = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert first_stop["Status"] == "DONE", (
        f"expected the positive-control stop to transition to DONE, got {first_stop['Status']!r}"
    )
    first_ended_at = first_stop["EndedAt"]

    # Negative: stopping the same, now-terminal run again must be rejected.
    err = _client_error(
        lambda: appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"expected a second StopExperimentRun on an already-DONE run to raise "
        f"BadRequestException, got {err['Code']!r}"
    )
    not_running = f"Experiment run {run_number} for experiment definition {def_id} is not running."
    assert err["Message"] == not_running, f"expected message {not_running!r}, got {err['Message']!r}"

    # Effect absent: the terminal state recorded by the first stop must be untouched.
    after = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert after["Status"] == "DONE", (
        f"the rejected second stop must not have mutated Status, got {after['Status']!r}"
    )
    assert after["EndedAt"] == first_ended_at, (
        f"the rejected second stop must not have mutated EndedAt: "
        f"expected {first_ended_at!r}, got {after['EndedAt']!r}"
    )


def _flag_key() -> str:
    return "flag" + uuid.uuid4().hex[:10]


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
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
        Tags=_TAGS,
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
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version["VersionNumber"]
        )
    )
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id: str, env_id: str, profile_id: str, version_number) -> int:
    """Start (and wait for completion of) a deployment of the configuration profile version to
    the environment, using a custom zero-duration/zero-bake deployment strategy so it reaches
    COMPLETE quickly. AppConfig requires an existing, completed deployment for a configuration
    profile before an experiment run can be started against the feature flag it stores (a
    RUNNING deployment leaves the environment in state DEPLOYING, which StartExperimentRun
    rejects)."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
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
        f"expected the deployment to reach COMPLETE, got {completed['State']!r}"
    )
    return deployment_number


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key, name=None):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
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
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, def_id))
    return def_id, resp


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
