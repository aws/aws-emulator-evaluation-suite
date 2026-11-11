"""experiment-run-events-recorded-in-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "experiment-run-events-recorded-in-order"
GROUP = "ordering"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a run starts and stops, ListExperimentRunEvents returns exactly the stop and start
    events, newest first (RUN_STOPPED is Items[0]), with OccurredAt non-increasing across the list.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "expflag"
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    exp_id, _ = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    started = appconfig.start_experiment_run(ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)
    run_number = started["Run"]
    ctx.on_cleanup(lambda: _ignore_conflict(lambda: appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)))

    # OccurredAt has whole-second resolution at best: events a second apart order by time, not by
    # the target's tie-break.
    time.sleep(1.1)
    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)
    assert stopped["Status"] == "DONE", f"expected stop_experiment_run to report DONE, got {stopped['Status']}"

    events = appconfig.list_experiment_run_events(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number)["Items"]
    assert len(events) == 2, f"expected exactly a start and a stop event (no exposure/override update), got {events}"

    timestamps = [e["OccurredAt"] for e in events]
    for newer, older in zip(timestamps, timestamps[1:]):
        assert newer >= older, f"events are not in reverse-chronological (newest-first) order: {timestamps}"

    assert events[0]["EventType"] == "RUN_STOPPED", f"newest event should be RUN_STOPPED, got {events[0]}"
    assert events[-1]["EventType"] == "RUN_STARTED", f"oldest event should be RUN_STARTED, got {events[-1]}"


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ignore_conflict(fn):
    """Teardown stop of the run: a run the body already stopped answers ConflictException or
    BadRequestException "... is not running.", and a gone one ResourceNotFoundException; that is
    the end state. Any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        error = e.response["Error"]
        stopped = error["Code"] == "BadRequestException" and error.get("Message", "").endswith("is not running.")
        if error["Code"] not in ("ConflictException", "ResourceNotFoundException") and not stopped:
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_environment(
        ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS")))
    return env_id


def _create_feature_flag_profile(ctx, app_id, flag_key):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS")))
    content = json.dumps({
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
        "version": "1",
    }).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=content, ContentType="application/json",
    )["VersionNumber"]
    # The profile delete refuses while a hosted version remains; LIFO teardown deletes it first.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number)))
    return profile_id, version_number


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_no_bake_deployment_strategy(ctx):
    """A custom zero-duration, zero-bake strategy avoids AppConfig.AllAtOnce's ~10min

    FinalBakeTimeInMinutes, which would otherwise blow past the check's overall timeout
    just waiting for a prerequisite deployment to leave the BAKING state.
    """
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)))
    return strategy_id


def _deploy_configuration(ctx, app_id, env_id, profile_id, version_number):
    """AppConfig requires an existing (completed) deployment before an experiment run can start."""
    appconfig = ctx.client("appconfig")
    strategy_id = _create_no_bake_deployment_strategy(ctx)
    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = deployment["DeploymentNumber"]
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number),
        lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK", "REVERTED"),
        timeout_s=90.0,
        interval_s=3.0,
    )


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key,
                                   control_weight=50.0, treatment_weight=50.0):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        # "$region" here is an AudienceRule evaluation-context variable the caller supplies
        # when resolving a flag, not the AWS region the API call runs in (ctx.region) — the
        # literal is an arbitrary targeting predicate, never evaluated by this check.
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": control_weight},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": treatment_weight}],
        Tags=_TAGS,
    )
    exp_id = resp["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY")))
    return exp_id, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
