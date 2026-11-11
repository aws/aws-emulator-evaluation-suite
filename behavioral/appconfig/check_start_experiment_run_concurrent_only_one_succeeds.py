"""start-experiment-run-concurrent-only-one-succeeds."""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-run-concurrent-only-one-succeeds"
GROUP = "concurrency"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent StartExperimentRun calls on one experiment definition yield exactly one
    RUNNING run; the other gets ConflictException with the in-flight duplicate-run message or the
    already-running message, as AppConfig allows one active run per definition."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = f"flag{uuid.uuid4().hex[:8]}"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    def_id = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    def _start():
        return appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_start) for _ in range(2)]
        for f in futures:
            try:
                results.append(("ok", f.result()))
            except ClientError as e:
                results.append(("err", e.response["Error"]))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    # Register the stop before any assertion below can raise -- a definition with an
    # active run rejects DeleteExperimentDefinition (even DeleteType=DESTROY), so an
    # assertion failure here must not leave the app-level cleanup unable to tear down.
    if successes:
        run_number = successes[0][1]["Run"]

        def _cleanup_stop():
            try:
                appconfig.stop_experiment_run(
                    ApplicationIdentifier=app_id,
                    ExperimentDefinitionIdentifier=def_id,
                    Run=run_number,
                )
            except ClientError as exc:
                # ConflictException: the run already reached a terminal state.
                code = exc.response["Error"]["Code"]
                if code not in ("ResourceNotFoundException", "ConflictException"):
                    raise

        ctx.on_cleanup(_cleanup_stop)

    assert len(successes) == 1, f"expected exactly one successful start, got {len(successes)}"
    assert len(failures) == 1, f"expected exactly one rejected start, got {len(failures)}"
    err = failures[0][1]
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']}"
    # A loser that overlaps the winner's creation and one that arrives after it is RUNNING get
    # different documented messages; either is a correct refusal.
    in_flight = (
        f"Experiment run number {run_number} already exists for experiment definition {def_id}"
    )
    running = (
        f"Experiment definition {def_id} already has a running experiment. "
        "The current experiment run must be stopped before a run can be started."
    )
    expected = in_flight if err["Message"].startswith("Experiment run number") else running
    assert err["Message"] == expected, f"unexpected message: {err['Message']!r}"
    assert successes[0][1]["Status"] == "RUNNING", (
        f"expected the winning StartExperimentRun response to report RUNNING, "
        f"got {successes[0][1]['Status']!r}"
    )

    fetched = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert fetched["Status"] == "RUNNING", (
        f"expected an independent GetExperimentRun read to report RUNNING, got {fetched['Status']!r}"
    )
    assert fetched["Run"] == run_number, f"expected Run {run_number}, got {fetched['Run']}"


# ===== helpers =====
_PREFIX = "sim2real-appconfig-"


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name(_PREFIX + "app-"))["Id"]

    def _cleanup():
        try:
            appconfig.delete_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name(_PREFIX + "env-")
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return env_id


def _create_feature_flag_profile(ctx, app_id, flag_key):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name(_PREFIX + "profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

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

    # DeleteConfigurationProfile is refused while a hosted version exists: LIFO deletes it first.
    def _cleanup_version():
        try:
            appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=profile_id,
                VersionNumber=version["VersionNumber"],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_version)
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id, env_id, profile_id, version_number):
    """AppConfig requires an existing, completed deployment for a configuration profile
    before an experiment run can be started against the feature flag it stores."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name(_PREFIX + "depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )
    strategy_id = strategy["Id"]

    def _cleanup_strategy():
        try:
            appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_strategy)

    dep = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = dep["DeploymentNumber"]

    budget = 30.0
    left = ctx.time_left()
    if left is not None:
        budget = max(1.0, min(budget, left - 15.0))
    deadline = time.monotonic() + budget
    last_state = None
    while time.monotonic() < deadline:
        got = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        last_state = got["State"]
        if last_state == "COMPLETE":
            return deployment_number
        time.sleep(1.5)
    raise AssertionError(
        f"deployment did not COMPLETE within {budget:.0f}s; last state={last_state!r}"
    )


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name(_PREFIX + "expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
    )
    def_id = resp["Id"]

    def _cleanup():
        # A definition whose run is still settling to a terminal state refuses the delete with
        # ConflictException; retry every 2 s for up to 120 s, then raise.
        deadline = time.monotonic() + 120
        while True:
            try:
                appconfig.delete_experiment_definition(
                    ApplicationIdentifier=app_id,
                    ExperimentDefinitionIdentifier=def_id,
                    DeleteType="DESTROY",
                )
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return def_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
