"""experiment-run-start-active-complete-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-start-active-complete-lifecycle"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-start-active-complete-lifecycle"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun creates a run that is RUNNING immediately, and GetExperimentRun
    reflects that same status (and the run number/StartedAt) without any manual poke."""
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
    assert run_resp["Status"] == "RUNNING", f"expected RUNNING immediately after start, got {run_resp['Status']!r}"
    run_number = run_resp["Run"]
    ctx.on_cleanup(lambda: _safe_stop_experiment_run(ctx, app_id, def_id, run_number))
    assert run_number >= 1, f"expected a 1-based run number, got {run_number!r}"
    assert "StartedAt" in run_resp, f"expected StartedAt on the start response, got keys {sorted(run_resp)!r}"

    stable = _poll_until(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        ),
        lambda resp: resp["Status"] == "RUNNING",
        timeout_s=20.0,
    )
    assert stable["Run"] == run_number, f"expected GetExperimentRun to echo Run={run_number!r}, got {stable['Run']!r}"
    assert stable["Status"] == "RUNNING", f"expected GetExperimentRun to reflect RUNNING, got {stable['Status']!r}"
    assert stable["StartedAt"] == run_resp["StartedAt"], (
        f"expected GetExperimentRun StartedAt to match the start response exactly, "
        f"got {stable['StartedAt']!r} vs {run_resp['StartedAt']!r}"
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
    assert completed["State"] == "COMPLETE", f"expected deployment to reach COMPLETE, got {completed['State']!r}"
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


def _safe_stop_experiment_run(ctx, app_id: str, def_id: str, run_number: int) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
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
