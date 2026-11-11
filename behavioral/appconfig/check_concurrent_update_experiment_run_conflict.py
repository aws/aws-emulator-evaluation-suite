"""concurrent-update-experiment-run-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-update-experiment-run-conflict"
GROUP = "concurrency"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-update-experiment-run-conflict"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent StartExperimentRun calls on one definition yield exactly one RUNNING run and ConflictException
    for every other racer; after the run is stopped, N concurrent UpdateExperimentRun calls on the terminal run
    all get BadRequestException and none changes its Description."""
    appconfig = ctx.client("appconfig")
    setup = _create_experiment_definition(ctx, appconfig)
    app_id = setup["app_id"]
    def_id = setup["def_id"]

    racer_count = 6

    def _start(_i: int):
        return appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )

    successes: list[dict] = []
    start_conflict_codes: list[tuple[str | None, str | None]] = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_start, i) for i in range(racer_count)]
        for fut in as_completed(futures):
            try:
                successes.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                start_conflict_codes.append(_error_of(exc))

    assert len(successes) == 1, f"expected exactly 1 StartExperimentRun winner, got {len(successes)}"
    assert len(start_conflict_codes) == racer_count - 1, (
        f"expected {racer_count - 1} losing racers, got {len(start_conflict_codes)}: {start_conflict_codes}"
    )
    assert all(c == "ConflictException" for c, _ in start_conflict_codes), (
        f"losing racers must all get ConflictException, got {start_conflict_codes}"
    )
    # Which refusal a loser sees depends on how far the winner got; each is AWS's exact wording.
    conflicts = {
        f"Experiment run number 1 already exists for experiment definition {def_id}",
        f"Experiment definition {def_id} already has a running experiment. The current experiment run "
        "must be stopped before a run can be started.",
    }
    # The in-flight refusal ends in a retry interval AWS chooses, so only its prefix is pinned.
    assert all(
        message in conflicts or message.startswith("A previous operation for run 1 is in flight, retry in ") for _, message in start_conflict_codes
    ), (
        f"losing racers must carry an exact StartExperimentRun conflict message, got {start_conflict_codes}"
    )

    winner = successes[0]
    assert winner["Status"] == "RUNNING", f"winner status was {winner['Status']!r}, not RUNNING"
    run_number = winner["Run"]

    runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert len(runs) == 1 and runs[0]["Run"] == run_number, "exactly one run must exist, not a partial write"

    # Positive control: UpdateExperimentRun must actually work against a RUNNING run before
    # the DONE-run race below can mean anything -- otherwise "every racer gets
    # BadRequestException" would be indistinguishable from "UpdateExperimentRun always fails".
    positive_description = "positive-control"
    positive_update = appconfig.update_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        Run=run_number,
        Description=positive_description,
    )
    assert positive_update["Status"] == "RUNNING", (
        f"positive-control update on a RUNNING run returned status {positive_update['Status']!r}, not RUNNING"
    )
    assert positive_update["Description"] == positive_description, (
        f"positive-control update did not persist: expected Description={positive_description!r}, "
        f"got {positive_update.get('Description')!r}"
    )

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert stopped["Status"] == "DONE", f"stop_experiment_run returned status {stopped['Status']!r}, not DONE"

    def _update(i: int):
        return appconfig.update_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
            Description=f"racer-{i}",
        )

    update_codes: list[tuple[str | None, str | None]] = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_update, i) for i in range(racer_count)]
        for fut in as_completed(futures):
            try:
                fut.result()
                update_codes.append((None, None))
            except Exception as exc:  # noqa: BLE001
                update_codes.append(_error_of(exc))

    terminal = (
        "BadRequestException",
        f"Cannot update experiment run {run_number} for experiment definition {def_id} because it is already terminal.",
    )
    assert all(error == terminal for error in update_codes), (
        f"all concurrent updates against a DONE run must get BadRequestException, got {update_codes}"
    )

    final = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert final["Status"] == "DONE", f"final get_experiment_run status was {final['Status']!r}, not DONE"
    assert final.get("Description") == positive_description, (
        "a concurrent UpdateExperimentRun mutated a DONE run's Description: expected the "
        f"positive-control value {positive_description!r}, got {final.get('Description')!r}"
    )


def _error_of(exc: Exception) -> tuple[str | None, str | None]:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return None, None


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"condition not met within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _create_experiment_definition(ctx, appconfig) -> dict[str, Any]:
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-cexpapp-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-cexpenv-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-cexpprofile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    flag_key = "sim2realcflag"
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
    # A profile refuses deletion while hosted versions exist, so this teardown runs first.
    ctx.on_cleanup(lambda: _delete_hosted_version(appconfig, app_id, profile_id, version_number))

    # StartExperimentRun needs a completed deployment of the profile in the environment; a custom
    # strategy with zero duration and bake time settles it in seconds (AllAtOnce bakes 10 minutes).
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-cexpstrategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    # AWS returns DeploymentState as "COMPLETE", matching the model, but EnvironmentState as
    # PascalCase "ReadyForDeployment", unlike the model's "READY_FOR_DEPLOYMENT".
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment["DeploymentNumber"]
        )["State"],
        lambda state: state == "COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    # StartExperimentRun also rejects with ConflictException while the environment still
    # reports Deploying, even after the deployment itself reaches COMPLETE.
    _poll_until(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"],
        lambda state: state == "ReadyForDeployment",
        timeout_s=120.0,
        interval_s=3.0,
    )

    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-cexpdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    def_id = definition["Id"]
    # The default DeleteType archives the definition, which still blocks DeleteApplication.
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    )
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "def_id": def_id}



def _delete_hosted_version(appconfig, app_id, profile_id, version_number):
    """Teardown DeleteHostedConfigurationVersion; ResourceNotFoundException is already gone."""
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
