"""experiment-definition-delete-while-running-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-definition-delete-while-running-rejected"
GROUP = "e2e"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-delete-while-running"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteExperimentDefinition on a definition with a RUNNING run raises BadRequestException and
    leaves the definition in place; after the run stops, the same delete succeeds.
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

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    run_number = run_resp["Run"]
    assert run_resp["Status"] == "RUNNING", (
        f"expected StartExperimentRun to report RUNNING immediately, got {run_resp['Status']!r}"
    )

    # break exactly one thing: try to destroy the definition while its run is active
    err = _client_error(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            DeleteType="DESTROY",
        )
    )
    assert err["Code"] == "BadRequestException", f"CODE_WAS={err['Code']!r}"
    running = f"Experiment definition {exp_id} cannot be deleted while an experiment is running."
    assert err["Message"] == running, f"expected message {running!r}, got {err['Message']!r}"

    # effect absent: the definition must still exist, unmodified
    still_there = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    assert still_there["Id"] == exp_id, (
        f"the rejected delete must not have disturbed the definition's identity: "
        f"expected {exp_id!r}, got {still_there['Id']!r}"
    )
    assert still_there["Status"] == "ACTIVE", (
        f"the rejected delete must leave the definition ACTIVE, got {still_there['Status']!r}"
    )

    # positive control: stop the run, then the same delete call succeeds
    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )

    def _run_done():
        r = appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
        return r["Status"] == "DONE"

    assert _poll_until(_run_done, timeout_s=30.0), "run never reached DONE"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
    )
    final_err = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )
    )
    assert final_err["Code"] == "ResourceNotFoundException", (
        f"once the blocking run is stopped, the identical delete must succeed and the definition "
        f"must be genuinely gone; got {final_err['Code']!r}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {exp_id} could not be found for account {account}."
    )
    assert final_err["Message"] == not_found, (
        f"expected message {not_found!r}, got {final_err['Message']!r}"
    )


def _poll_until(probe, *, timeout_s: float = 30.0, interval_s: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
