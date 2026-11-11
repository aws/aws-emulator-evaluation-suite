"""e2e-experiment-full-flow-create-run-observe-teardown."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-experiment-full-flow-create-run-observe-teardown"
GROUP = "e2e"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Experiment lifecycle: deploy a flag, start a run (RUN_STARTED event, RUNNING), stop it
    (DONE), destroy the definition; Get and StartExperimentRun on the dead id return not-found."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "simflag"
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key)
    deployment_number = _deploy_feature_flag(ctx, app_id, env_id, profile_id, flag_key)

    # the deploy that makes the flag live is itself part of this end-to-end journey:
    # confirm it reached its terminal COMPLETE state and is visible via both
    # GetDeployment and ListDeployments before any experiment run is started against it.
    deploy_state = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda d: d["State"] == "COMPLETE",
        timeout_s=30.0,
        interval_s=2.0,
        description="deployment reaching COMPLETE",
    )
    assert deploy_state["State"] == "COMPLETE", f"deployment did not complete: {deploy_state['State']}"

    deployments = appconfig.list_deployments(ApplicationId=app_id, EnvironmentId=env_id)["Items"]
    assert deployment_number in {d["DeploymentNumber"] for d in deployments}, (
        f"deployment {deployment_number} missing from ListDeployments: {deployments}"
    )

    definition = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)
    def_id = definition["Id"]
    assert definition["Status"] == "IDLE"

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        ExposurePercentage=50.0,
    )
    run_number = run_resp["Run"]
    assert run_resp["Status"] == "RUNNING"

    # the experiment definition itself flips to ACTIVE while a run is live
    active_definition = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert active_definition["Status"] == "ACTIVE"

    events = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )["Items"],
        lambda items: any(e["EventType"] == "RUN_STARTED" for e in items),
        timeout_s=30.0,
        interval_s=2.0,
        description="RUN_STARTED event recorded",
    )
    assert any(e["EventType"] == "RUN_STARTED" for e in events)

    run_state = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert run_state["Status"] == "RUNNING"

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )

    stopped_run_state = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert stopped_run_state["Status"] == "DONE"
    assert "EndedAt" in stopped_run_state, f"stopped run missing EndedAt: {stopped_run_state}"

    # the definition reverts to IDLE once its only run is stopped
    idle_definition = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert idle_definition["Status"] == "IDLE"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        DeleteType="DESTROY",
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment "
        f"Definition Identifier {def_id} could not be found for account {account_id}."
    )
    code, message = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )
    )
    assert code == "ResourceNotFoundException", code
    assert message == not_found, f"expected {not_found!r}, got {message!r}"

    # a destroyed definition is not just unreadable, it is unusable: a mutation
    # against the dead id must fail with the same specific not-found code.
    mutate_code, mutate_message = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            ExposurePercentage=50.0,
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"starting a run against a destroyed definition should 404, got {mutate_code}"
    )
    assert mutate_message == not_found, f"expected {not_found!r}, got {mutate_message!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0, description="condition"):
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last = None
    while _time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last value: {last}")


def _mgmt_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


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


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_mgmt_tags()
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_mgmt_tags()
    )["Id"]
    # this environment gets an actual deployment below, which AppConfig's
    # account-level deletion protection can otherwise block at teardown time.
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str) -> str:
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_mgmt_tags(),
    )["Id"]
    ctx.on_cleanup(
        lambda: _delete_profile_and_versions(
            appconfig, ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="BYPASS",
        )
    )
    content = {
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
        "version": "1",
    }
    appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
        ContentType="application/json",
    )
    return profile_id


def _create_experiment_definition(
    ctx,
    app_id: str,
    profile_id: str,
    env_id: str,
    flag_key: str,
    *,
    name: str | None = None,
    # a literal fed to AppConfig's own targeting-rule DSL (evaluated server-side
    # against request context), not an SDK/API region pin -- any placeholder
    # value works here.
    audience_rule: str = '(eq $region "us-east-1")',
    control_weight: float = 50.0,
    treatment_weight: float = 50.0,
    hypothesis: str | None = None,
) -> dict:
    appconfig = ctx.client("appconfig")
    kwargs = dict(
        ApplicationIdentifier=app_id,
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule=audience_rule,
        Control={"FlagValue": {"Enabled": False}, "Weight": control_weight},
        Treatments=[{"FlagValue": {"Enabled": True}, "Weight": treatment_weight}],
        Tags=_mgmt_tags(),
    )
    if hypothesis is not None:
        kwargs["Hypothesis"] = hypothesis
    return appconfig.create_experiment_definition(**kwargs)


def _deploy_feature_flag(ctx, app_id: str, env_id: str, profile_id: str, flag_key: str) -> int:
    import json as _json
    import time as _time

    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_mgmt_tags(),
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    content = _json.dumps(
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
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    deadline = _time.monotonic() + 60.0
    while _time.monotonic() < deadline:
        state = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
        if state == "ReadyForDeployment":
            return deployment_number
        _time.sleep(2.0)
    raise AssertionError("environment never reached ReadyForDeployment after deployment")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
