"""get-experiment-run-invalid-id-not-found."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags

CHECK = "get-experiment-run-invalid-id-not-found"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-experiment-run-invalid-id"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetExperimentRun for a run number that never existed under a real definition returns
    ResourceNotFoundException, while the real run number still fetches successfully."""
    appconfig = ctx.client("appconfig")
    flag_key = ctx.unique_name("flag-")
    base = _create_base(ctx, flag_key)
    app_id = base["app_id"]

    definition = _create_experiment_definition(ctx, base, flag_key)
    def_id = definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_definition(appconfig, app_id, def_id))

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    real_run_number = started["Run"]

    # Positive control: the real run number fetches successfully.
    real_run = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=real_run_number
    )
    assert real_run["Status"] == "RUNNING", f"expected RUNNING, got {real_run['Status']!r}"

    never_existed_run_number = real_run_number + 9999
    code, code_msg = _error(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=never_existed_run_number,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Experiment run with Experiment Definition Id {def_id}, Application Id {app_id}, and "
        f"Experiment Run {never_existed_run_number} could not be found for account {account}."
    ), f"unexpected message: {code_msg!r}"

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=real_run_number
    )


def _error(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_definition(appconfig, app_id, def_id):
    # If the check body aborted before reaching its own stop_experiment_run call, an
    # active run leaves DeleteExperimentDefinition(DeleteType=DESTROY) rejected with
    # BadRequestException -- stop anything still RUNNING first so cleanup is not
    # short-circuited by the failure it is trying to clean up after.
    try:
        runs = appconfig.list_experiment_runs(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        ).get("Items", [])
        for one_run in runs:
            if one_run.get("Status") == "RUNNING":
                appconfig.stop_experiment_run(
                    ApplicationIdentifier=app_id,
                    ExperimentDefinitionIdentifier=def_id,
                    Run=one_run["Run"],
                )
    except botocore.exceptions.ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except botocore.exceptions.ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number, timeout=90.0):
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        deployment = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        last_state = deployment["State"]
        if last_state == "COMPLETE":
            return
        if last_state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state {last_state}")
        time.sleep(3)
    raise AssertionError(
        f"deployment did not reach COMPLETE within {timeout}s (last state {last_state})"
    )


def _create_base(ctx, flag_key):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="BYPASS",
        )
    )

    content = json.dumps(
        {
            "version": "1",
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )

    # AppConfig experiments require the flag to already be deployed to the
    # environment before a run can be started (experimentation prerequisites).
    # Use a custom zero-duration/zero-bake strategy (rather than the predefined
    # AppConfig.AllAtOnce, which carries a 10-minute CloudWatch bake window) so
    # the deployment reaches COMPLETE quickly.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number)

    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id}


def _treatment(weight, enabled=True):
    return {"Weight": weight, "FlagValue": {"Enabled": enabled}}


def _create_experiment_definition(ctx, base, flag_key, name=None):
    appconfig = ctx.client("appconfig")
    return appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=flag_key,
        AudienceRule="(eq 1 1)",
        Control=_treatment(50.0),
        Treatments=[_treatment(50.0)],
        Tags=_TAGS,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
