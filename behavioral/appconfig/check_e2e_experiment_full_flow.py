"""e2e-experiment-full-flow."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-experiment-full-flow"
GROUP = "e2e"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Experiment lifecycle: a started run reaches RUNNING with a RUN_STARTED event, stopping it reaches DONE with
    RUN_STOPPED, and destroying the definition makes GetExperimentDefinition return ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    flag_key = f"flag{uuid.uuid4().hex[:10]}"

    application = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))
    app_id = application["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"))
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-ff-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: _delete_profile_and_versions(
            appconfig, ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = json.dumps(
        {"flags": {flag_key: {"name": flag_key}}, "values": {flag_key: {"enabled": True}}, "version": "1"}
    ).encode("utf-8")
    hosted_version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )

    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )
    strategy_id = strategy["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(hosted_version["VersionNumber"]),
        DeploymentStrategyId=strategy_id,
    )
    deployment_number = deployment["DeploymentNumber"]
    final_deployment = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda d: d["State"] == "COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final_deployment["State"] == "COMPLETE", (
        f"expected deployment {deployment_number} to reach COMPLETE, got {final_deployment['State']!r}"
    )


    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-behav-expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
    )
    def_id = definition["Id"]
    assert definition["Status"] == "IDLE", f"expected freshly created definition IDLE, got {definition['Status']!r}"

    started = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    run_number = started["Run"]
    assert started["Status"] == "RUNNING", f"expected StartExperimentRun to report RUNNING, got {started['Status']!r}"

    running_definition = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert running_definition["Status"] == "ACTIVE", (
        f"expected definition to flip to ACTIVE while a run is live, got {running_definition['Status']!r}"
    )

    events = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )["Items"],
        lambda items: any(e.get("EventType") == "RUN_STARTED" for e in items),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert any(e["EventType"] == "RUN_STARTED" for e in events), (
        f"expected a RUN_STARTED event in run {run_number}'s history, got {events}"
    )

    stopped = appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert stopped["Status"] == "DONE", f"expected StopExperimentRun to report DONE, got {stopped['Status']!r}"

    final_run = _poll_until(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        ),
        lambda r: r["Status"] == "DONE",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert final_run["Status"] == "DONE", f"expected run {run_number} to settle DONE, got {final_run['Status']!r}"
    assert "EndedAt" in final_run, f"expected a terminal run to carry EndedAt, got keys {sorted(final_run)}"

    # the definition itself must fall back out of ACTIVE once its only run has stopped
    idle_definition = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert idle_definition["Status"] == "IDLE", (
        f"expected definition to revert to IDLE once the run stopped, got {idle_definition['Status']!r}"
    )

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
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
    assert code == "ResourceNotFoundException", (
        f"expected GetExperimentDefinition to 404 after DESTROY delete, got code {code!r}"
    )
    assert message == not_found, f"expected {not_found!r}, got {message!r}"




def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS
    raises, because a target ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
