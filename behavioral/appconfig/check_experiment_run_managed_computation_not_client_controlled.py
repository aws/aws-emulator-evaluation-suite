"""experiment-run-managed-computation-not-client-controlled."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-managed-computation-not-client-controlled"
GROUP = "server-side"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-managed-computation"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The service assigns run number, status, StartedAt and treatment Keys the client never sends.

    A second start while run 1 is RUNNING is refused with ConflictException and creates nothing;
    after run 1 is stopped the same call succeeds as run 2.
    """
    appconfig = ctx.client("appconfig")
    setup = _create_experiment_setup(ctx)
    exp = _create_experiment_definition(ctx, setup)

    # TreatmentInput has no Key member, so any Key here is server-assigned.
    assert exp["Control"]["Key"], "server must assign a Key the client never sent"
    assert exp["Treatments"][0]["Key"], "server must assign a Key the client never sent"

    run1 = appconfig.start_experiment_run(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert run1["Run"] == 1, "server assigns the first run number, not the caller"
    assert run1["Status"] == "RUNNING", "server sets the initial status; caller supplied none"
    assert run1["StartedAt"], "server stamps StartedAt"

    snapshot = run1["ExperimentDefinitionSnapshot"]
    assert snapshot["Control"]["Key"] == exp["Control"]["Key"], (
        f"expected snapshot Control.Key {exp['Control']['Key']!r}, got {snapshot['Control']['Key']!r}"
    )
    assert snapshot["Treatments"][0]["Key"] == exp["Treatments"][0]["Key"], (
        f"expected snapshot Treatments[0].Key {exp['Treatments'][0]['Key']!r}, "
        f"got {snapshot['Treatments'][0]['Key']!r}"
    )
    assert snapshot["FlagKey"] == setup["flag_key"], (
        f"expected snapshot FlagKey {setup['flag_key']!r}, got {snapshot['FlagKey']!r}"
    )

    fetched = appconfig.get_experiment_run(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"], Run=1
    )
    assert fetched["Status"] == "RUNNING", f"expected RUNNING on independent read, got {fetched['Status']!r}"
    assert fetched["ExperimentDefinitionSnapshot"]["Control"]["Key"] == exp["Control"]["Key"], (
        "independent GetExperimentRun read must report the same server-assigned Control.Key"
    )
    assert fetched["StartedAt"] == run1["StartedAt"], (
        "independent GetExperimentRun read must report the same server-stamped StartedAt"
    )

    err = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
        )
    )
    assert err["Code"] == "ConflictException", (
        f"expected ConflictException while run 1 is RUNNING, got {err['Code']!r}"
    )
    conflict = (
        f"Experiment definition {exp['Id']} already has a running experiment. "
        "The current experiment run must be stopped before a run can be started."
    )
    assert err["Message"] == conflict, f"expected message {conflict!r}, got {err['Message']!r}"

    runs_after_rejection = appconfig.list_experiment_runs(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )["Items"]
    assert len(runs_after_rejection) == 1, (
        f"expected exactly 1 run after the rejected concurrent start, got {len(runs_after_rejection)}"
    )
    assert runs_after_rejection[0]["Run"] == 1, (
        f"expected the surviving run to be Run 1, got {runs_after_rejection[0]['Run']!r}"
    )

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"], Run=1
    )
    assert stopped["Status"] == "DONE", f"expected DONE on the StopExperimentRun response itself, got {stopped['Status']!r}"

    terminal = appconfig.get_experiment_run(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"], Run=1
    )
    assert terminal["Status"] == "DONE", (
        f"expected DONE on an independent GetExperimentRun read after StopExperimentRun, got {terminal['Status']!r}"
    )
    assert terminal.get("EndedAt") is not None, (
        "independent GetExperimentRun read after an explicit stop must report EndedAt"
    )

    run2 = appconfig.start_experiment_run(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert run2["Run"] == 2, f"expected server to assign run number 2 after run 1 finished, got {run2['Run']!r}"
    assert run2["Status"] == "RUNNING", f"expected RUNNING on the restored start, got {run2['Status']!r}"


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_application_with_retry(appconfig, app_id, attempts=5, delay_s=2.0):
    """Retry DeleteApplication, which can conflict while just-deleted children propagate."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            appconfig.delete_application(ApplicationId=app_id)
            return
        except ClientError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay_s)


def _create_experiment_setup(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-expapp-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _delete_application_with_retry(appconfig, app_id))
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    flag_key = "expflag"
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": False}},
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
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
    # AppConfig requires an existing (completed) deployment for a configuration
    # profile/environment before StartExperimentRun will accept it.
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _deploy_configuration(ctx, app_id, env_id, profile_id, version_number):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
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
    _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK", "REVERTED"),
    )



def _create_experiment_definition(ctx, setup, name=None):
    appconfig = ctx.client("appconfig")
    exp = appconfig.create_experiment_definition(
        ApplicationIdentifier=setup["app_id"],
        Name=name or ctx.unique_name("exp-"),
        ConfigurationProfileIdentifier=setup["profile_id"],
        EnvironmentIdentifier=setup["env_id"],
        FlagKey=setup["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )

    def _cleanup():
        try:
            for item in appconfig.list_experiment_runs(
                ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
            ).get("Items", []):
                if item.get("Status") == "RUNNING":
                    try:
                        appconfig.stop_experiment_run(
                            ApplicationIdentifier=setup["app_id"],
                            ExperimentDefinitionIdentifier=exp["Id"],
                            Run=item["Run"],
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=setup["app_id"],
                ExperimentDefinitionIdentifier=exp["Id"],
                DeleteType="DESTROY",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return exp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
