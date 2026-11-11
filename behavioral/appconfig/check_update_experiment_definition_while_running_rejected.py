"""update-experiment-definition-while-running-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-experiment-definition-while-running-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentDefinition is refused with ConflictException while a run is RUNNING and
    leaves Hypothesis unchanged; the same update succeeds once the run is stopped."""
    appconfig = ctx.client("appconfig")
    tags_ = {"sim2real:managed": "true", "sim2real": CHECK}
    app_id = _create_application(ctx, tags_)
    env_id = _create_environment(ctx, app_id, tags_)
    flag_key = "simflag"
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key, tags_)
    _deploy_feature_flag(ctx, app_id, env_id, profile_id, flag_key, tags_)

    original_hypothesis = "original hypothesis"
    changed_hypothesis = "changed hypothesis"

    definition = _create_experiment_definition(
        ctx, app_id, profile_id, env_id, flag_key, hypothesis=original_hypothesis, tags=tags_
    )
    def_id = definition["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            DeleteType="DESTROY",
        )
    )
    assert definition["Hypothesis"] == original_hypothesis, (
        f"CreateExperimentDefinition did not round-trip Hypothesis: expected "
        f"{original_hypothesis!r}, got {definition['Hypothesis']!r}"
    )

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, ExposurePercentage=50.0
    )
    run_number = run_resp["Run"]
    ctx.on_cleanup(lambda: _stop_run_if_running(appconfig, app_id, def_id, run_number))

    code, message = _error(
        lambda: appconfig.update_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Hypothesis=changed_hypothesis,
        )
    )
    assert code == "ConflictException", (
        f"UpdateExperimentDefinition against a definition with an active RUNNING run should be "
        f"rejected with ConflictException, got {code!r}"
    )
    expected = (
        f"Cannot update experiment definition {def_id} with status ACTIVE. Stop the current "
        f"experiment run before updating the experiment definition."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert unchanged["Hypothesis"] == original_hypothesis, (
        f"the rejected update mutated the definition anyway: expected Hypothesis "
        f"{original_hypothesis!r}, got {unchanged['Hypothesis']!r}"
    )

    appconfig.stop_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    appconfig.update_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=def_id,
        Hypothesis=changed_hypothesis,
    )
    changed = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert changed["Hypothesis"] == changed_hypothesis, (
        f"the identical update did not take effect once the run was stopped: expected Hypothesis "
        f"{changed_hypothesis!r}, got {changed['Hypothesis']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _delete_version_if_present(appconfig, app_id: str, profile_id: str, version: int) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _stop_run_if_running(appconfig, app_id: str, def_id: str, run_number: int) -> None:
    run = appconfig.get_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
    )
    if run["Status"] == "RUNNING":
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, Run=run_number
        )


def _create_application(ctx, tags: dict) -> str:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=tags
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str, tags: dict) -> str:
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=tags
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str, tags: dict) -> str:
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=tags,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    content = {
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
        "version": "1",
    }
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: _delete_version_if_present(appconfig, app_id, profile_id, version_number)
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
    # $region is an AudienceRule variable matched against a caller-supplied client attribute,
    # not the SDK region, so it need not track ctx.region.
    audience_rule: str = '(eq $region "us-east-1")',
    control_weight: float = 50.0,
    treatment_weight: float = 50.0,
    hypothesis: str | None = None,
    tags: dict | None = None,
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
    )
    if hypothesis is not None:
        kwargs["Hypothesis"] = hypothesis
    if tags is not None:
        kwargs["Tags"] = tags
    return appconfig.create_experiment_definition(**kwargs)


def _deploy_feature_flag(
    ctx, app_id: str, env_id: str, profile_id: str, flag_key: str, tags: dict
) -> int:
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=tags,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
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
        lambda: _delete_version_if_present(appconfig, app_id, profile_id, version_number)
    )
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    import time as _time

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
