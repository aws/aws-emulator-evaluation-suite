"""start-experiment-run-invalid-treatment-allocation-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "start-experiment-run-invalid-treatment-allocation-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun with TreatmentOverrides naming an undefined treatment key raises
    BadRequestException and creates no run; the same call with a defined key starts a RUNNING run.
    """
    appconfig = ctx.client("appconfig")
    setup = _create_experiment_definition(ctx, appconfig)
    app_id = setup["app_id"]
    def_id = setup["def_id"]
    treatment_key = setup["treatment_key"]

    err = _error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            TreatmentOverrides={"Inline": {"entity-1": "nosuchtr"}},
        )
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err}"
    expected_message = (
        "Invalid treatment name: nosuchtr. "
        f"Valid treatment names are: [{setup['control_key']}, {treatment_key}]"
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert runs == [], f"invalid allocation must not create a run, found {runs}"

    still_idle = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert still_idle["Status"] == "IDLE", f"expected IDLE after rejected run, got {still_idle['Status']}"

    started = _start_experiment_run_retrying(
        appconfig, app_id, def_id, TreatmentOverrides={"Inline": {"entity-1": treatment_key}}
    )
    assert started["Status"] == "RUNNING", f"expected RUNNING for valid treatment key, got {started['Status']}"
    run_number = started["Run"]
    ctx.on_cleanup(
        lambda: appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )
    )

    runs_after = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert len(runs_after) == 1 and runs_after[0]["Run"] == run_number, (
        f"expected exactly the started run {run_number!r} in the list, got {runs_after!r}"
    )


def _error(fn: Callable[[], Any]):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _start_experiment_run_retrying(
    appconfig, app_id: str, def_id: str, *, timeout_s: float = 60.0, interval_s: float = 3.0, **kwargs
):
    """StartExperimentRun rejects with ConflictException while the environment still
    reports Deploying, even briefly after its deployment has reached Complete. Retry
    (bounded) on that specific transient conflict rather than asserting immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appconfig.start_experiment_run(
                ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, **kwargs
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_experiment_definition(ctx, appconfig) -> dict:
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-expapp-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-expenv-")
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-expprofile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    flag_key = "sim2realflag"
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode()
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    # DeleteConfigurationProfile is refused while a hosted version survives; LIFO runs this first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    # StartExperimentRun requires an existing (completed) deployment for the configuration
    # profile in the target environment -- confirmed against real AWS, which rejects
    # StartExperimentRun with BadRequestException ("There must be an existing deployment for
    # configuration profile ...") otherwise. The predefined "AppConfig.AllAtOnce" strategy
    # carries a 10-minute FinalBakeTimeInMinutes on real AWS, so use a custom strategy with
    # zero deployment duration and zero bake time so the deployment settles in seconds.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-expstrategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    # NOTE: despite the documented SCREAMING_SNAKE_CASE enums, the real wire values are
    # PascalCase ("Complete", "ReadyForDeployment") -- confirmed against real AWS.
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment["DeploymentNumber"]
        )["State"],
        lambda state: state == "Complete",
        timeout_s=60.0,
        interval_s=2.0,
    )
    # StartExperimentRun also rejects with ConflictException while the environment still
    # reports Deploying, even after the deployment itself reaches Complete.
    _poll_until(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"],
        lambda state: state == "ReadyForDeployment",
        timeout_s=120.0,
        interval_s=3.0,
    )

    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
    )
    def_id = definition["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    )
    return {
        "app_id": app_id,
        "env_id": env_id,
        "profile_id": profile_id,
        "def_id": def_id,
        "control_key": definition["Control"]["Key"],
        "treatment_key": definition["Treatments"][0]["Key"],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
