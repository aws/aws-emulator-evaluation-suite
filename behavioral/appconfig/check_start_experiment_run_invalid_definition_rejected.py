"""start-experiment-run-invalid-definition-rejected."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-experiment-run-invalid-definition-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-start-experiment-run-invalid-definition-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun against a nonexistent experiment definition id is rejected, creates no
    run anywhere, and a real definition in the same application still starts normally -- visibly,
    via an independent read at the destination, not just in the mutating call's own response."""
    appconfig = ctx.client("appconfig")
    flag_key = ctx.unique_name("flag-")
    base = _create_base(ctx, flag_key)
    app_id = base["app_id"]

    real_definition = _create_experiment_definition(ctx, base, flag_key)
    real_def_id = real_definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_definition(appconfig, app_id, real_def_id))

    bogus_def_id = ctx.unique_name("sim2real-behav-nonexistent-def-")
    err = _error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=bogus_def_id
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent definition id, got {err!r}"
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {bogus_def_id} could not be found for account {account_id}."
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # No run was accidentally created against the real definition as a side effect.
    real_runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=real_def_id
    )["Items"]
    assert real_runs == [], (
        f"expected no runs against the real definition after the rejected call, got {real_runs!r}"
    )

    # Positive control: the real definition still starts a run normally.
    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=real_def_id
    )
    run_number = started["Run"]
    assert started["Status"] == "RUNNING", (
        f"expected RUNNING in the start response, got {started['Status']!r}"
    )

    # Terminal read: independent of the mutating start_experiment_run call -- the run must be
    # visible as RUNNING through list_experiment_runs, a different operation, at the destination.
    runs_after = appconfig.list_experiment_runs(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=real_def_id
    )["Items"]
    run_entry = next((r for r in runs_after if r["Run"] == run_number), None)
    assert run_entry is not None, (
        f"run {run_number} not visible via list_experiment_runs: {runs_after!r}"
    )
    assert run_entry["Status"] == "RUNNING", (
        f"expected RUNNING via independent list read, got {run_entry['Status']!r}"
    )

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=real_def_id,
        Run=run_number,
    )


def _error(fn):
    """Call fn(); return the botocore error (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


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
