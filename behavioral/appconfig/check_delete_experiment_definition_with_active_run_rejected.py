"""delete-experiment-definition-with-active-run-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-experiment-definition-with-active-run-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "appconfig-delete-experiment-definition-with-active-run-rejected",
}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteExperimentDefinition while a run is RUNNING is rejected with BadRequestException and leaves the
    definition and run intact; once the run is stopped the same delete succeeds and removes the run too."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    base = _setup_experiment_base(ctx)
    created = _create_experiment_definition(ctx, appconfig, base)
    def_id = created["Id"]

    start = appconfig.start_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    run_number = start["Run"]
    assert start["Status"] == "RUNNING", (
        f"expected StartExperimentRun to report RUNNING immediately, got {start['Status']!r}"
    )

    code, message = _client_error(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=base["app_id"],
            ExperimentDefinitionIdentifier=def_id,
            DeleteType="DESTROY",
        )
    )
    assert code == "BadRequestException", code
    expected = f"Experiment definition {def_id} cannot be deleted while an experiment is running."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the definition and its run must still exist.
    still_there = appconfig.get_experiment_definition(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    assert still_there["Status"] == "ACTIVE", (
        f"the rejected delete must leave the definition ACTIVE, got {still_there['Status']!r}"
    )
    still_running = appconfig.get_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    assert still_running["Status"] == "RUNNING", (
        f"the rejected delete must leave the run RUNNING, got {still_running['Status']!r}"
    )

    # Positive control: once the blocking run is stopped, the identical delete succeeds and
    # cascades to the run it owned.
    appconfig.stop_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    appconfig.delete_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        ExperimentDefinitionIdentifier=def_id,
        DeleteType="DESTROY",
    )
    not_found = (
        f"Experiment Definition with Application Identifier {base['app_id']} and Experiment "
        f"Definition Identifier {def_id} could not be found for account {account_id}."
    )
    def_code, def_message = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
        )
    )
    assert def_code == "ResourceNotFoundException", def_code
    assert def_message == not_found, f"expected {not_found!r}, got {def_message!r}"
    run_code, run_message = _client_error(
        lambda: appconfig.get_experiment_run(
            ApplicationIdentifier=base["app_id"],
            ExperimentDefinitionIdentifier=def_id,
            Run=run_number,
        )
    )
    assert run_code == "ResourceNotFoundException", run_code
    assert run_message == not_found, f"expected {not_found!r}, got {run_message!r}"


_AUDIENCE_RULE = '(eq $country "US")'


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS
    raises, because a target ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
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


def _setup_experiment_base(ctx, flag_key="expflag1"):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _delete_profile_and_versions(
            appconfig, ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    content = {
        "version": "1",
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
    }
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
        ContentType="application/json",
    )["VersionNumber"]

    # Experiments require an existing deployment of the flag to the environment. Use a
    # custom zero-bake-time strategy so the deployment reaches COMPLETE quickly instead of
    # sitting in the 10-minute default bake window of the predefined AllAtOnce strategy.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment["DeploymentNumber"])

    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _wait_for_deployment_complete(
    appconfig, app_id, env_id, deployment_number, timeout_s=240.0, interval_s=5.0
):
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last = None
    while _time.monotonic() < deadline:
        last = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if last["State"] == "COMPLETE":
            return last
        if last["State"] in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment failed: {last}")
        _time.sleep(interval_s)
    raise AssertionError(f"deployment not complete within {timeout_s}s; last={last!r}")


def _create_experiment_definition(ctx, appconfig, base, name=None):
    name = name or ctx.unique_name("sim2real-exp-")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=base["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def_id = resp["Id"]

    def _cleanup():
        try:
            for r in appconfig.list_experiment_runs(
                ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
            ).get("Items", []):
                if r.get("Status") == "RUNNING":
                    try:
                        appconfig.stop_experiment_run(
                            ApplicationIdentifier=base["app_id"],
                            ExperimentDefinitionIdentifier=def_id,
                            Run=r["Run"],
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=base["app_id"],
                ExperimentDefinitionIdentifier=def_id,
                DeleteType="DESTROY",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
