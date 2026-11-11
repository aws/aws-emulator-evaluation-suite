"""experiment-run-scheduled-end-time-auto-stop."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags

CHECK = "experiment-run-scheduled-end-time-auto-stop"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appconfig"]

_END_TIME_TOKENS = {
    "EndTime",
    "EndAt",
    "Duration",
    "DurationInMinutes",
    "Ttl",
    "TimeToLive",
    "ScheduledEndTime",
    "ExpiresAt",
    "ExpirationTime",
}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An experiment run has no end time: StartExperimentRun takes no end-time member, and a run
    stays RUNNING without EndedAt for a 20 s window, reaching DONE with EndedAt only on
    StopExperimentRun.
    """
    appconfig = ctx.client("appconfig")

    start_run_input = appconfig.meta.service_model.operation_model("StartExperimentRun").input_shape
    present = set(start_run_input.members) & _END_TIME_TOKENS
    assert not present, (
        f"StartExperimentRun unexpectedly gained an end-time-style field: {present} -- "
        "a scheduled-end-time auto-stop scenario is now implementable; replace the "
        "poll below with a real StartExperimentRun(...EndTime=...) -> auto-DONE check"
    )

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
    assert started["Status"] == "RUNNING", f"expected RUNNING, got {started['Status']!r}"
    ctx.on_cleanup(lambda: _safe_stop_run(appconfig, app_id, def_id, run_number))

    # The last read always lands at or after the deadline, so RUNNING holds across the window.
    deadline = time.monotonic() + 20.0
    poll_count = 0
    while True:
        fetched = appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )
        assert fetched["Status"] == "RUNNING", (
            f"run auto-transitioned to Status={fetched['Status']!r} with no explicit "
            "StopExperimentRun call -- AppConfig has no scheduled end-time to expire on"
        )
        assert fetched.get("EndedAt") is None, (
            f"a RUNNING run unexpectedly reports EndedAt={fetched.get('EndedAt')!r}"
        )
        unexpected = set(fetched) & _END_TIME_TOKENS
        assert not unexpected, (
            f"GetExperimentRun response unexpectedly carries an end-time-style field: {unexpected}"
        )
        poll_count += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(4)
    assert poll_count >= 3, f"observation window only polled {poll_count} times"

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert stopped["Status"] == "DONE", f"expected DONE, got {stopped['Status']!r}"

    final = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert final["Status"] == "DONE", f"expected DONE on independent read, got {final['Status']!r}"
    assert final.get("EndedAt") is not None, "a DONE run must report EndedAt"


def _ignore_not_found(call):
    """Run a teardown call; only an already-gone resource counts as clean."""
    try:
        return call()
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return None


def _safe_delete_definition(appconfig, app_id, def_id):
    _ignore_not_found(lambda: appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
    ))


def _safe_stop_run(appconfig, app_id, def_id, run_number):
    """Stop the run only while it is RUNNING: a stop of a DONE run is rejected."""
    ids = {"ApplicationIdentifier": app_id, "ExperimentDefinitionIdentifier": def_id, "Run": run_number}
    current = _ignore_not_found(lambda: appconfig.get_experiment_run(**ids))
    if current is not None and current.get("Status") == "RUNNING":
        _ignore_not_found(lambda: appconfig.stop_experiment_run(**ids))


def _safe_delete_version(appconfig, app_id, profile_id, version_number):
    _ignore_not_found(lambda: appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
    ))


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


_TAGS = {"sim2real-behav-check": "experiment-run-scheduled-end-time-auto-stop"}


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
    ctx.on_cleanup(
        lambda: _safe_delete_version(appconfig, app_id, profile_id, version_number)
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )

    # AppConfig experiments require the flag to already be deployed to the
    # environment before a run can be started (experimentation prerequisites).
    # A zero-duration/zero-bake strategy avoids AppConfig.AllAtOnce's 10-minute bake window.
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
