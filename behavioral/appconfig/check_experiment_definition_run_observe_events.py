"""experiment-definition-run-observe-events."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-definition-run-observe-events"
GROUP = "e2e"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-lifecycle"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create, start, stop and delete an experiment definition, asserting at each stage the observed
    status transitions and event log growth, then that the definition is gone.
    """
    appconfig = ctx.client("appconfig")

    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id, flag_key = _create_feature_flag_profile(ctx, app_id)
    _deploy_configuration(ctx, app_id, env_id, profile_id)

    exp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    exp_id = exp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, exp_id))
    assert exp["Status"] == "IDLE"

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    run_number = run_resp["Run"]
    assert run_resp["Status"] == "RUNNING"

    # the definition flips ACTIVE while a run is in progress
    def _definition_active():
        d = appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )
        return d["Status"] == "ACTIVE"

    assert _poll_until(_definition_active, timeout_s=30.0), "definition never became ACTIVE"

    # the run-started event must show up in the run's event log
    def _has_run_started_event():
        events = appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            Run=run_number,
        )["Items"]
        return any(e["EventType"] == "RUN_STARTED" for e in events)

    assert _poll_until(_has_run_started_event, timeout_s=30.0), "RUN_STARTED event never observed"

    run_state = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert run_state["Status"] == "RUNNING"
    # StartExperimentRun was called with no ExposurePercentage; real AWS reports the
    # run as 0% exposed by default (the docs: "Set to 0 to validate the experiment
    # before exposing production users") rather than defaulting to full exposure.
    assert run_state["ExposurePercentage"] == 0.0, (
        f"expected ExposurePercentage=0.0 (no exposure requested), got "
        f"{run_state['ExposurePercentage']!r}"
    )

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )

    def _run_done():
        r = appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
        return r["Status"] == "DONE"

    assert _poll_until(_run_done, timeout_s=30.0), "run never reached DONE"

    def _has_run_stopped_event():
        events = appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            Run=run_number,
        )["Items"]
        return any(e["EventType"] == "RUN_STOPPED" for e in events)

    assert _poll_until(_has_run_stopped_event, timeout_s=30.0), "RUN_STOPPED event never observed"

    # once the run ends and there is no other active run, the definition reverts to IDLE
    def _definition_idle():
        d = appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )
        return d["Status"] == "IDLE"

    assert _poll_until(_definition_idle, timeout_s=30.0), "definition never reverted to IDLE"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {exp_id} could not be found for account {account}."
    )
    get_err = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )
    )
    assert get_err["Code"] == "ResourceNotFoundException", get_err
    assert get_err["Message"] == not_found, f"expected message {not_found!r}, got {get_err['Message']!r}"

    # a deleted definition is not just unreadable -- it is unusable: starting a new run
    # against the dead id must fail the same way, not silently create orphaned state
    start_err = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )
    )
    assert start_err["Code"] == "ResourceNotFoundException", start_err
    assert start_err["Message"] == not_found, f"expected message {not_found!r}, got {start_err['Message']!r}"


def _poll_until(probe, *, timeout_s: float = 30.0, interval_s: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available and must not be reported as
    a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_experiment_definition(ctx, app_id, exp_id) -> None:
    try:
        ctx.client("appconfig").delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        )
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id: str) -> tuple[str, str]:
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
        lambda: _safe_call(
            lambda: appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        )
    )
    flag_key = ctx.unique_name("flag-").replace("_", "-")
    content = {
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
        "version": "1",
    }
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
            )
        )
    )
    return profile_id, flag_key


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _deploy_configuration(ctx, app_id: str, env_id: str, profile_id: str) -> None:
    """Deploy the profile's hosted config version 1 to the environment and wait
    for it to complete -- StartExperimentRun requires an existing deployment for
    the configuration profile before an experiment can be started against it."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )
    strategy_id = strategy["Id"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
        )
    )
    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion="1",
    )
    deployment_number = deployment["DeploymentNumber"]

    def _deployment_complete():
        d = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        return d["State"] in ("COMPLETE", "BAKING")

    assert _poll_until(_deployment_complete, timeout_s=60.0), "deployment never completed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
