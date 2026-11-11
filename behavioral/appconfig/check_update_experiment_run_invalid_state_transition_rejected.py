"""update-experiment-run-invalid-state-transition-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "update-experiment-run-invalid-state-transition-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-experiment-run-invalid-state-transition"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentRun on a run that already completed (Status=DONE) is rejected
    with BadRequestException and does not change its ExposurePercentage, enforcing a
    forward-only state machine -- while updating a still-RUNNING run succeeds."""
    appconfig = ctx.client("appconfig")
    prereqs = _create_feature_flag_app(ctx)
    _deploy_feature_flag(ctx, prereqs)
    name = ctx.unique_name("sim2real-behav-expdef-")
    definition = _create_experiment_definition(ctx, prereqs, name)
    exp_id = definition["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_experiment_definition(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=exp_id,
                DeleteType="DESTROY",
            )
        )
    )

    # run 1: start, then stop it so it reaches the terminal DONE state
    run1 = appconfig.start_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        ExposurePercentage=10.0,
    )
    run1_number = run1["Run"]
    appconfig.stop_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run1_number,
    )
    stopped = _poll_until(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=prereqs["app_id"],
            ExperimentDefinitionIdentifier=exp_id,
            Run=run1_number,
        ),
        lambda r: r["Status"] == "DONE",
        timeout_s=_budget_s(ctx, 30.0),
    )
    if stopped["Status"] != "DONE" and _budget_spent(ctx):
        raise TimeoutError(
            "the stopped experiment run reaching DONE: the run budget ended first; not graded"
        )
    assert stopped["Status"] == "DONE", f"stopped run never reached DONE, got {stopped!r}"

    # attempting to update the now-DONE run is rejected
    code, message = _error(
        lambda: appconfig.update_experiment_run(
            ApplicationIdentifier=prereqs["app_id"],
            ExperimentDefinitionIdentifier=exp_id,
            Run=run1_number,
            ExposurePercentage=20.0,
        )
    )
    assert code == "BadRequestException", f"got={code!r}"
    expected = (
        f"Cannot update experiment run {run1_number} for experiment definition {exp_id} "
        f"because it is already terminal."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: exposure percentage on the stopped run is unchanged
    still_stopped = appconfig.get_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run1_number,
    )
    assert still_stopped["Status"] == "DONE"
    assert still_stopped["ExposurePercentage"] == 10.0

    # positive control: a second, still-RUNNING run can be updated
    run2 = appconfig.start_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        ExposurePercentage=10.0,
    )
    run2_number = run2["Run"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.stop_experiment_run(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=exp_id,
                Run=run2_number,
            )
        )
    )
    updated = appconfig.update_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run2_number,
        ExposurePercentage=20.0,
    )
    assert updated["Status"] == "RUNNING"
    assert updated["ExposurePercentage"] == 20.0

    # independent read confirms the accepted update was actually persisted
    confirmed = appconfig.get_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run2_number,
    )
    assert confirmed["Status"] == "RUNNING"
    assert confirmed["ExposurePercentage"] == 20.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0):
    """Poll probe() until predicate holds or timeout_s passes; return the last result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
    return last


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_cleanup(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_feature_flag_app(ctx) -> dict[str, Any]:
    """Create an Application with a feature-flag ConfigurationProfile + hosted
    configuration version + Environment, wired for experiments."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        )
    )

    flag_key = ctx.unique_name("flag-").replace("_", "-")
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=profile_id,
                VersionNumber=version_number,
            )
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        )
    )

    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id, "flag_key": flag_key}


def _deploy_feature_flag(ctx, prereqs: dict[str, Any]) -> None:
    """StartExperimentRun requires an existing (completed) deployment of the
    configuration profile to the environment -- deploy the hosted version created by
    _create_feature_flag_app and wait for that deployment to reach COMPLETE."""
    appconfig = ctx.client("appconfig")
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
        lambda: _safe_cleanup(
            lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
        )
    )
    deployment_number = appconfig.start_deployment(
        ApplicationId=prereqs["app_id"],
        EnvironmentId=prereqs["env_id"],
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=prereqs["profile_id"],
        ConfigurationVersion="1",
    )["DeploymentNumber"]
    last = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=prereqs["app_id"],
            EnvironmentId=prereqs["env_id"],
            DeploymentNumber=deployment_number,
        ),
        lambda d: d["State"] == "COMPLETE",
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
    )
    if last["State"] != "COMPLETE" and _budget_spent(ctx):
        raise TimeoutError(
            "the deployment reaching COMPLETE: the run budget ended first; not graded"
        )
    if last["State"] != "COMPLETE":
        raise AssertionError(f"deployment did not reach COMPLETE; last state={last['State']!r}")


def _create_experiment_definition(ctx, prereqs: dict[str, Any], name: str) -> dict[str, Any]:
    appconfig = ctx.client("appconfig")
    return appconfig.create_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=prereqs["profile_id"],
        EnvironmentIdentifier=prereqs["env_id"],
        FlagKey=prereqs["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
