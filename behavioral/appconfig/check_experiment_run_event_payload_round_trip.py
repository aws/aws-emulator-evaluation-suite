"""experiment-run-event-payload-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "experiment-run-event-payload-round-trip"
GROUP = "representation"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-run-event-payload"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The RUN_STARTED event's ExposurePercentage and OccurredAt match what StartExperimentRun
    returned, with TriggeredBy USER: no truncation or rounding drift in ListExperimentRunEvents."""
    appconfig = ctx.client("appconfig")
    prereqs = _setup_experiment_prereqs(ctx)
    definition = _create_experiment_definition(ctx, prereqs)
    exp_id = definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment(appconfig, prereqs["app_id"], exp_id))

    start_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=prereqs["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        ExposurePercentage=45.5,
    )
    run_number = start_resp["Run"]
    ctx.on_cleanup(
        lambda: _safe_stop_run(appconfig, prereqs["app_id"], exp_id, run_number)
    )
    assert start_resp["ExposurePercentage"] == 45.5, (
        f"expected StartExperimentRun to echo ExposurePercentage=45.5, got {start_resp['ExposurePercentage']!r}"
    )
    started_at = start_resp["StartedAt"]

    items = _poll_until(
        lambda: appconfig.list_experiment_run_events(
            ApplicationIdentifier=prereqs["app_id"],
            ExperimentDefinitionIdentifier=exp_id,
            Run=run_number,
        )["Items"],
        lambda items: any(e["EventType"] == "RUN_STARTED" for e in items),
        timeout_s=30,
        interval_s=2,
    )
    run_started_events = [e for e in items if e["EventType"] == "RUN_STARTED"]
    assert len(run_started_events) == 1, (
        f"expected exactly one RUN_STARTED event, got {len(run_started_events)}: {run_started_events!r}"
    )
    event = run_started_events[0]

    assert event["ExposurePercentage"] == 45.5, (
        f"RUN_STARTED event ExposurePercentage drifted from StartExperimentRun's 45.5, "
        f"got {event['ExposurePercentage']!r}"
    )
    assert event["TriggeredBy"] == "USER", (
        f"expected RUN_STARTED TriggeredBy='USER' for an API-initiated run, got {event['TriggeredBy']!r}"
    )
    time_delta = abs((event["OccurredAt"] - started_at).total_seconds())
    assert time_delta < 2.0, (
        f"event timestamp drift: RUN_STARTED OccurredAt={event['OccurredAt']!r} vs "
        f"StartExperimentRun StartedAt={started_at!r} (delta={time_delta}s)"
    )


def _error_code(fn: Callable[[], Any]) -> str | None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


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


def _setup_experiment_prereqs(ctx, flag_key: str = "expflag") -> dict[str, str]:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-appcfg-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-appcfg-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-appcfg-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="BYPASS",
        )
    )

    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=_make_flag_content(flag_key),
        ContentType="application/json",
    )["VersionNumber"]
    # DeleteConfigurationProfile (and so DeleteApplication) is rejected with
    # BadRequestException while a hosted configuration version still exists under it.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    # StartExperimentRun requires an existing deployment of the profile to the environment;
    # a zero-duration/zero-bake strategy reaches COMPLETE almost immediately.
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


def _safe_stop_run(appconfig, app_id: str, exp_id: str, run_number: int) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
