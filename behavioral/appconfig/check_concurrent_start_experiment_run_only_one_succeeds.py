"""concurrent-start-experiment-run-only-one-succeeds."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-experiment-run-only-one-succeeds"
GROUP = "concurrency"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent StartExperimentRun calls against the same definition race under
    optimistic locking; exactly one creates a RUNNING run and the other gets ConflictException."""
    appconfig = ctx.client("appconfig")

    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "concflag"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)

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
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number)

    exp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": 50},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": 50}],
        Tags=_TAGS,
    )
    exp_id = exp["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    )

    def _start():
        return appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_start) for _ in range(2)]
        results: list[Any] = []
        errors: list[tuple[str, str]] = []
        for fut in futures:
            try:
                results.append(fut.result())
            except ClientError as err:
                errors.append((err.response["Error"]["Code"], err.response["Error"]["Message"]))

    assert len(results) == 1, f"expected exactly one StartExperimentRun to succeed, got {len(results)}"
    assert len(errors) == 1, f"expected exactly one StartExperimentRun to fail, got {len(errors)}"
    loser_code, loser_message = errors[0]
    assert loser_code == "ConflictException", f"loser error was {errors[0]!r}, not ConflictException"
    expected = _conflict_message(exp_id, loser_message)
    assert loser_message == expected, f"loser message {loser_message!r} is not a StartExperimentRun conflict"

    winner = results[0]
    run_number = winner["Run"]
    assert winner["Status"] == "RUNNING", f"expected winner Status RUNNING, got {winner['Status']!r}"

    # Register the stop before further assertions so a failure below still leaves the run stoppable.
    ctx.on_cleanup(
        lambda: appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    )

    fetched = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert fetched["Status"] == "RUNNING", (
        f"independent GetExperimentRun expected Status RUNNING, got {fetched['Status']!r}"
    )
    assert fetched["Run"] == run_number, (
        f"independent GetExperimentRun expected Run {run_number!r}, got {fetched['Run']!r}"
    )


_IN_FLIGHT = "A previous operation for run 1 is in flight, retry in "


def _conflict_message(def_id, message):
    """The StartExperimentRun conflict text a loser carries; which one depends on how far the winner
    got, and the in-flight one ends in a retry interval AWS chooses, so that number is read back."""
    if message.startswith(_IN_FLIGHT):
        seconds = message.removeprefix(_IN_FLIGHT).removesuffix("s.")
        return f"{_IN_FLIGHT}{seconds if seconds.isdigit() else '<seconds>'}s."
    if message.startswith("Experiment run number "):
        return f"Experiment run number 1 already exists for experiment definition {def_id}"
    return (
        f"Experiment definition {def_id} already has a running experiment. The current experiment run "
        "must be stopped before a run can be started."
    )


_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "appconfig-concurrent-start-experiment-run-only-one-succeeds",
}


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
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout}s (last state {last_state})")


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str) -> tuple[str, int]:
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-ffprofile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    content = json.dumps(
        {
            "version": "1",
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    version_number = version["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
    return profile_id, version_number


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
