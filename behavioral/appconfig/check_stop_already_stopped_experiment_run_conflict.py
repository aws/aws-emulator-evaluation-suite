"""stop-already-stopped-experiment-run-conflict."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-already-stopped-experiment-run-conflict"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-stop-already-stopped-experiment-run-conflict"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once a stopped run is listed as DONE, a second StopExperimentRun is rejected with
    BadRequestException and its exact message, the run's terminal state stays untouched, and a
    fresh run on the same definition can still be started and stopped."""
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
    run_number = started["Run"]

    first_stop = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert first_stop["Status"] == "DONE", (
        f"expected DONE after the first (legitimate) stop, got {first_stop['Status']!r}"
    )
    original_ended_at = first_stop["EndedAt"]

    # The stop guard reads an eventually consistent index of run statuses; wait until the index
    # lists the run as DONE so the second stop is judged against the terminal state.
    _wait_run_listed_done(ctx, appconfig, app_id, def_id, run_number)

    err = _error(
        lambda: appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"expected BadRequestException on a stop of an already-DONE run, got {err!r}"
    )
    expected_message = f"Experiment run {run_number} for experiment definition {def_id} is not running."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # State is unchanged by the rejected second stop.
    after = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert after["Status"] == "DONE", (
        f"expected DONE to persist after the rejected second stop, got {after['Status']!r}"
    )
    assert after["EndedAt"] == original_ended_at, (
        f"expected EndedAt unchanged by the rejected second stop: "
        f"{original_ended_at!r} -> {after['EndedAt']!r}"
    )

    # Positive control: a fresh run on the same definition starts and stops normally, proving the
    # rejection above is scoped to the terminal run and not to the definition as a whole.
    second_started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert second_started["Run"] != run_number, (
        f"expected a fresh run number, got the same run {second_started['Run']!r} again"
    )
    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        Run=second_started["Run"],
    )

    # Terminal read is an independent GetExperimentRun, not the mutating StopExperimentRun's own
    # response.
    second_after = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        Run=second_started["Run"],
    )
    assert second_after["Status"] == "DONE", (
        f"expected the fresh run to read back DONE after its stop, got {second_after['Status']!r}"
    )
    assert second_after["EndedAt"] is not None, (
        "expected the fresh run's independent read to report a non-null EndedAt after stop"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_run_listed_done(ctx, appconfig, app_id, def_id, run_number, cap_s=30.0):
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + min(cap_s, budget_s)
    while True:
        items = appconfig.list_experiment_runs(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Status="DONE"
        )["Items"]
        listed = [item["Run"] for item in items]
        if run_number in listed:
            return
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait for run {run_number} to be listed as DONE ended; not graded"
                )
            raise AssertionError(
                f"run {run_number} never listed as DONE after its stop; last DONE runs {listed!r}"
            )
        time.sleep(2.0)


def _error(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_definition(appconfig, app_id, def_id):
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
            ApplicationId=app_id, ConfigurationProfileId=profile_id
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
    # DeleteConfigurationProfile is refused while a hosted version survives; LIFO runs this first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
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
