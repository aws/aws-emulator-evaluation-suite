"""experiment-run-cross-application-isolation-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-run-cross-application-isolation-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-cross-application-isolation"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun with an ExperimentDefinitionIdentifier from a different application raises
    ResourceNotFoundException and creates no run: definitions are scoped to their application.
    """
    appconfig = ctx.client("appconfig")
    setup_a = _create_experiment_setup(ctx)
    exp = _create_experiment_definition(ctx, setup_a)

    app_b_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-expappb-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_b_id))

    err = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_b_id, ExperimentDefinitionIdentifier=exp["Id"]
        )
    )
    assert err["Code"] == "ResourceNotFoundException", err
    account = ctx.client("sts").get_caller_identity()["Account"]
    expected = (
        f"Experiment Definition with Application Identifier {app_b_id} and Experiment Definition "
        f"Identifier {exp['Id']} could not be found for account {account}."
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    runs_under_a = appconfig.list_experiment_runs(
        ApplicationIdentifier=setup_a["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )["Items"]
    assert runs_under_a == [], "the cross-application call must not have created a run"

    # Positive control: the identical operation against the definition's real
    # owning application succeeds and actually starts a run.
    started = appconfig.start_experiment_run(
        ApplicationIdentifier=setup_a["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert started["Status"] == "RUNNING", started
    assert started["Run"] == 1, started

    # Independent read at the destination, not the mutating call's own echo.
    confirmed = appconfig.get_experiment_run(
        ApplicationIdentifier=setup_a["app_id"],
        ExperimentDefinitionIdentifier=exp["Id"],
        Run=started["Run"],
    )
    assert confirmed["Status"] == "RUNNING", confirmed

    appconfig.stop_experiment_run(
        ApplicationIdentifier=setup_a["app_id"],
        ExperimentDefinitionIdentifier=exp["Id"],
        Run=started["Run"],
    )

    # Terminal assertion: an independent read confirms the stop actually took
    # effect, rather than terminating on stop_experiment_run's own response.
    stopped = appconfig.get_experiment_run(
        ApplicationIdentifier=setup_a["app_id"],
        ExperimentDefinitionIdentifier=exp["Id"],
        Run=started["Run"],
    )
    assert stopped["Status"] == "DONE", stopped


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_experiment_setup(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-expapp-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
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
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
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
