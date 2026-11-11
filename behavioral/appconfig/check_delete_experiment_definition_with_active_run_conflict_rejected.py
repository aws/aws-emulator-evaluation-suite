"""delete-experiment-definition-with-active-run-conflict-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-experiment-definition-with-active-run-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteExperimentDefinition with an active run fails with BadRequestException, not the
    documented ConflictException, and keeps the definition; once the run is stopped it deletes."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    setup = _create_experiment_setup(ctx)
    exp = _create_experiment_definition(ctx, setup)
    assert exp["Status"] == "IDLE"

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert started["Status"] == "RUNNING"

    active_definition = appconfig.get_experiment_definition(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert active_definition["Status"] == "ACTIVE"

    code, message = _client_error(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=setup["app_id"],
            ExperimentDefinitionIdentifier=exp["Id"],
            DeleteType="DESTROY",
        )
    )
    assert code == "BadRequestException", code
    expected = f"Experiment definition {exp['Id']} cannot be deleted while an experiment is running."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The delete must not have happened: the definition is still fetchable and ACTIVE.
    still_active = appconfig.get_experiment_definition(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert still_active["Status"] == "ACTIVE"

    # Positive control: stopping the run clears the conflict and the delete succeeds.
    appconfig.stop_experiment_run(
        ApplicationIdentifier=setup["app_id"],
        ExperimentDefinitionIdentifier=exp["Id"],
        Run=started["Run"],
    )
    idle_definition = appconfig.get_experiment_definition(
        ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
    )
    assert idle_definition["Status"] == "IDLE"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=setup["app_id"],
        ExperimentDefinitionIdentifier=exp["Id"],
        DeleteType="DESTROY",
    )
    not_found = (
        f"Experiment Definition with Application Identifier {setup['app_id']} and Experiment "
        f"Definition Identifier {exp['Id']} could not be found for account {account_id}."
    )
    code_after, message_after = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=setup["app_id"], ExperimentDefinitionIdentifier=exp["Id"]
        )
    )
    assert code_after == "ResourceNotFoundException", code_after
    assert message_after == not_found, f"expected {not_found!r}, got {message_after!r}"

    # The destroy cascades: the run it once owned is gone too, not just the definition.
    run_code_after, run_message_after = _client_error(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=setup["app_id"],
            ExperimentDefinitionIdentifier=exp["Id"],
            Run=started["Run"],
        )
    )
    assert run_code_after == "ResourceNotFoundException", run_code_after
    assert run_message_after == not_found, f"expected {not_found!r}, got {run_message_after!r}"



def _client_error(fn):
    """Call fn() and return its (error code, error message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_profile_and_versions(appconfig, **profile):
    """Teardown: delete every hosted version, then the profile, because AWS refuses to delete a
    configuration profile that still has hosted versions."""
    ids = {
        "ApplicationId": profile["ApplicationId"],
        "ConfigurationProfileId": profile["ConfigurationProfileId"],
    }
    for page in appconfig.get_paginator("list_hosted_configuration_versions").paginate(**ids):
        for item in page["Items"]:
            appconfig.delete_hosted_configuration_version(**ids, VersionNumber=item["VersionNumber"])
    appconfig.delete_configuration_profile(**profile)


def _create_experiment_setup(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-expapp-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    env_id = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("env-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]
    ctx.on_cleanup(
        lambda: _delete_profile_and_versions(
            appconfig, ApplicationId=app_id, ConfigurationProfileId=profile_id
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
