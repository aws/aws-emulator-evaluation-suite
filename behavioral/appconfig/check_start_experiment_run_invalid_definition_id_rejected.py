"""start-experiment-run-invalid-definition-id-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-experiment-run-invalid-definition-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExperimentRun with an ExperimentDefinitionIdentifier over the 2048-character maximum
    raises BadRequestException and creates no run, while the real definition id starts one.
    """
    appconfig = ctx.client("appconfig")
    base = _setup_experiment_base(ctx)
    created = _create_experiment_definition(ctx, appconfig, base)
    def_id = created["Id"]

    malformed_id = "x" * 2049

    err = _error(
        lambda: appconfig.start_experiment_run(
            ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=malformed_id
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"expected BadRequestException for a {len(malformed_id)}-char "
        f"ExperimentDefinitionIdentifier (max 2048), got {err!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'experimentDefinitionIdentifier' "
        "failed to satisfy constraint: Member must have length less than or equal to 2048"
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # Effect absent: no run was created for the real definition.
    runs_before = appconfig.list_experiment_runs(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert runs_before == [], (
        f"expected no experiment runs for {def_id!r} after the rejected call, got {runs_before!r}"
    )

    # Positive control: the real, well-formed definition id starts successfully.
    start = appconfig.start_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    assert start["Status"] == "RUNNING", (
        f"expected the positive control to start RUNNING, got {start['Status']!r}"
    )
    run_number = start["Run"]

    runs_after = appconfig.list_experiment_runs(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )["Items"]
    assert len(runs_after) == 1, (
        f"expected exactly 1 experiment run for {def_id!r}, got {len(runs_after)}: {runs_after!r}"
    )
    assert runs_after[0]["Run"] == run_number, (
        f"expected the listed run to be {run_number!r}, got {runs_after[0]['Run']!r}"
    )

    appconfig.stop_experiment_run(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id, Run=run_number
    )


_AUDIENCE_RULE = '(eq $country "US")'


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _setup_experiment_base(ctx, flag_key="expflag1"):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-")
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
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
    # DeleteConfigurationProfile is refused while a hosted version survives; LIFO runs this first.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

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
