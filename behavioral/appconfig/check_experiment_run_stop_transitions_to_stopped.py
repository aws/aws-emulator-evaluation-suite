"""experiment-run-stop-transitions-to-stopped."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-run-stop-transitions-to-stopped"
GROUP = "state-machine"
SERVICES = ["appconfig"]
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-stop"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopExperimentRun on a RUNNING run transitions it to the terminal DONE status
    (AppConfig's terminal experiment-run state), and the owning definition reverts
    from ACTIVE back to IDLE."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_feature_flag_profile(ctx, app_id)
    flag_key = ctx.unique_name("sim2real-flag-")
    _deploy_feature_flag(ctx, app_id, env_id, profile_id, flag_key)

    created = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key=flag_key)
    exp_id = created["Id"]

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    run_number = started["Run"]
    assert started["Status"] == "RUNNING", f"expected RUNNING after start, got {started['Status']!r}"
    ctx.on_cleanup(lambda: _safe_stop_experiment_run(ctx, app_id, exp_id, run_number))

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=exp_id,
        Run=run_number,
        Result={"ExecutiveSummary": "sim2real-behavioral-test-stop"},
    )
    assert stopped["Status"] == "DONE", f"expected DONE from stop response, got {stopped['Status']!r}"
    assert stopped.get("EndedAt") is not None, f"expected EndedAt set on stop, got {stopped.get('EndedAt')!r}"
    assert stopped["EndedAt"] >= stopped["StartedAt"], (
        f"EndedAt {stopped['EndedAt']!r} precedes StartedAt {stopped['StartedAt']!r}"
    )

    got_run = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert got_run["Status"] == "DONE", f"expected DONE on independent read, got {got_run['Status']!r}"
    assert got_run["Result"]["ExecutiveSummary"] == "sim2real-behavioral-test-stop", (
        f"Result not round-tripped, got {got_run.get('Result')!r}"
    )

    final_def_status = _poll_until(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )["Status"],
        lambda status: status == "IDLE",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert final_def_status == "IDLE", f"expected owning definition back to IDLE, got {final_def_status!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    return profile_id


def _deploy_feature_flag(ctx, app_id, env_id, profile_id, flag_key):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": False}},
            "version": "1",
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    _poll_until(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"],
        lambda state: state == "ReadyForDeployment",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return deployment_number


def _safe_delete_experiment_definition(ctx, app_id, exp_id):
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            DeleteType="DESTROY",
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "ConflictException",
        ):
            raise


def _safe_stop_experiment_run(ctx, app_id, exp_id, run_number):
    appconfig = ctx.client("appconfig")
    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            Run=run_number,
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "ConflictException",
        ):
            raise


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key=None, name=None):
    appconfig = ctx.client("appconfig")
    flag_key = flag_key or ctx.unique_name("sim2real-flag-")
    name = name or ctx.unique_name("sim2real-exp-")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=name,
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule='(eq $country "US")',
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
    )
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, resp["Id"]))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
