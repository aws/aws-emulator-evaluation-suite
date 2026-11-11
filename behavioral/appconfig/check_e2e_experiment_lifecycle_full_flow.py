"""e2e-experiment-lifecycle-full-flow."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-experiment-lifecycle-full-flow"
GROUP = "e2e"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-lifecycle-full-flow"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Full experiment lifecycle: create -> start run -> events accumulate -> stop ->
    COMPLETED/DONE terminal state -> delete definition -> subsequent Get 404s."""
    appconfig = ctx.client("appconfig")
    prereqs = _setup_experiment_prereqs(ctx)

    definition = _create_experiment_definition(ctx, prereqs)
    exp_id = definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment(appconfig, prereqs["app_id"], exp_id))
    assert definition["Status"] == "IDLE", f"expected freshly created definition IDLE, got {definition['Status']!r}"

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    run_number = run_resp["Run"]
    assert run_resp["Status"] == "RUNNING", f"expected StartExperimentRun to return RUNNING, got {run_resp['Status']!r}"

    # Starting a run flips the parent definition from IDLE to ACTIVE.
    during_run = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert during_run["Status"] == "ACTIVE", f"expected definition ACTIVE while a run is in progress, got {during_run['Status']!r}"

    events = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=prereqs["app_id"],
            ExperimentDefinitionIdentifier=exp_id,
            Run=run_number,
        )["Items"],
        lambda items: any(e["EventType"] == "RUN_STARTED" for e in items),
        timeout_s=30,
        interval_s=2,
    )
    assert any(e["EventType"] == "RUN_STARTED" for e in events), f"expected a RUN_STARTED event, got event types {[e['EventType'] for e in events]!r}"

    stop_resp = appconfig.stop_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Run=run_number,
    )
    assert stop_resp["Status"] == "DONE", f"expected StopExperimentRun to return DONE, got {stop_resp['Status']!r}"

    final_run = appconfig.get_experiment_run(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id, Run=run_number
    )
    assert final_run["Status"] == "DONE", f"expected run to settle at DONE, got {final_run['Status']!r}"
    assert "EndedAt" in final_run, f"expected a terminal run to report EndedAt, got keys {sorted(final_run)!r}"

    # Stopping the run returns the parent definition to IDLE.
    after_stop = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert after_stop["Status"] == "IDLE", f"expected definition to return to IDLE after the run stopped, got {after_stop['Status']!r}"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {prereqs['app_id']} and Experiment "
        f"Definition Identifier {exp_id} could not be found for account {account_id}."
    )
    read_code, read_message = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
        )
    )
    assert read_code == "ResourceNotFoundException", f"expected Get on a destroyed definition to 404, got code {read_code!r}"
    assert read_message == not_found, f"expected {not_found!r}, got {read_message!r}"

    # A destroyed definition must be unusable, not just unreadable: a mutation
    # against the same dead id fails with the identical not-found code.
    mutate_code, mutate_message = _client_error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
        )
    )
    assert mutate_code == "ResourceNotFoundException", f"expected StartExperimentRun on a destroyed definition to 404, got code {mutate_code!r}"
    assert mutate_message == not_found, f"expected {not_found!r}, got {mutate_message!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
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


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 30.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _make_flag_content(flag_key: str) -> bytes:
    return json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")


def _wait_for_deployment_complete(
    appconfig, app_id: str, env_id: str, deployment_number: int, *, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if last["State"] == "COMPLETE":
            return last
        if last["State"] in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state: {last!r}")
        time.sleep(interval_s)
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s (last={last!r})")


def _setup_experiment_prereqs(ctx, flag_key: str = "expflag") -> dict[str, str]:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-appcfg-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-appcfg-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _delete_profile_and_versions(appconfig, ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )

    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=_make_flag_content(flag_key),
        ContentType="application/json",
    )["VersionNumber"]

    # StartExperimentRun requires an existing deployment of the configuration
    # profile to the environment. Deploy it now via a zero-duration/zero-bake
    # custom strategy so it reaches COMPLETE almost immediately.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-appcfg-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        ReplicateTo="NONE",
        FinalBakeTimeInMinutes=0,
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
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number)

    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _create_experiment_definition(ctx, prereqs: dict[str, str], name: str | None = None, **overrides: Any) -> dict[str, Any]:
    appconfig = ctx.client("appconfig")
    name = name or ctx.unique_name("sim2real-appcfg-exp-")
    params: dict[str, Any] = dict(
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
    params.update(overrides)
    return appconfig.create_experiment_definition(**params)


def _safe_delete_experiment(appconfig, app_id: str, exp_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
