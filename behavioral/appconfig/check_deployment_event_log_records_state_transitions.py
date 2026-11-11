"""deployment-event-log-records-state-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-event-log-records-state-transitions"
GROUP = 'deployment'
SERVICES = ['appconfig']

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")

# Modeled DeploymentEventType members.
_EVENT_TYPES = {
    "PERCENTAGE_UPDATED",
    "ROLLBACK_STARTED",
    "ROLLBACK_COMPLETED",
    "BAKE_TIME_STARTED",
    "DEPLOYMENT_STARTED",
    "DEPLOYMENT_COMPLETED",
    "REVERT_COMPLETED",
}
_TRIGGERED_BY = {"USER", "APPCONFIG", "CLOUDWATCH_ALARM", "INTERNAL_ERROR"}
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deployment-event-log"}

def _poll_until(probe, predicate, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Every page is read because AppConfig refuses a parent delete while any child survives.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _drain_and_delete_app(ac, app_id, timeout_s=180):
    """Stop in-flight deployments, wait environments out of transitional states, delete the
    application, and confirm it is gone. Raises rather than leaking silently."""
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        env_id = env["Id"]
        # A per-environment budget, so earlier environments cannot exhaust a later one's wait.
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id,
                EnvironmentId=env_id,
            )
        ):
            if dep.get("State") in _DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                    raise
        while time.monotonic() < deadline:
            if ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get(
                "State"
            ) not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(
                f"environment {env_id} never left {_ENV_TRANSITIONAL} during cleanup"
            )
    # Children first: AppConfig refuses DeleteApplication while children exist and
    # DeleteConfigurationProfile while hosted versions exist.
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(
            ApplicationId=app_id,
        )
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)
    # Its own budget, independent of the environment waits above.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ac.get_application(ApplicationId=app_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise AssertionError(
                f"unexpected error confirming application deletion: {code!r}"
            ) from exc
        time.sleep(1.0)
    raise AssertionError(f"application {app_id} still present after the cleanup deadline")


def _epoch(value) -> float:
    """Normalise a botocore datetime (or epoch number) to a comparable float."""
    if hasattr(value, "timestamp"):
        return value.timestamp()
    return float(value)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A completed deployment's EventLog runs newest-first from DEPLOYMENT_COMPLETED back to
    DEPLOYMENT_STARTED with modeled enum values and non-increasing OccurredAt, and the deployment
    echoes its strategy's parameters, timestamps and an empty AppliedExtensions list.
    """
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_name = ctx.unique_name("sim2real-behav-cp-")
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=cp_name, LocationUri="hosted", Tags=_TAGS
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        GrowthType="LINEAR",
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    version_label = "eventlog-v-one"
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"audit":"trail"}',
        ContentType="application/json",
        VersionLabel=version_label,
    )["VersionNumber"]

    started = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Description="sim2real-behav eventlog probe",
    )
    dep_num = started["DeploymentNumber"]
    assert dep_num == 1, f"first deployment in a fresh environment must be 1, got {dep_num}"

    final = _poll_until(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        ),
        lambda d: d.get("State") in _DEPLOYMENT_TERMINAL,
        timeout_s=90,
        interval_s=2.0,
        description="deployment reaching a terminal state",
    )
    assert final["State"] == "COMPLETE", (
        f"the deployment must succeed for the event log to be the success trail; got "
        f"{final['State']!r}"
    )

    # --- The strategy's parameters are copied onto the deployment, not just referenced.
    assert final["DeploymentStrategyId"] == ds_id, final["DeploymentStrategyId"]
    assert final["DeploymentDurationInMinutes"] == 0, final["DeploymentDurationInMinutes"]
    assert final["FinalBakeTimeInMinutes"] == 0, final["FinalBakeTimeInMinutes"]
    assert final["GrowthType"] == "LINEAR", final["GrowthType"]
    assert final["GrowthFactor"] == 100.0, final["GrowthFactor"]
    assert final["PercentageComplete"] == 100.0, final["PercentageComplete"]
    assert final["ConfigurationVersion"] == str(version), final["ConfigurationVersion"]
    assert final["ConfigurationName"] == cp_name, final["ConfigurationName"]
    assert final["ConfigurationLocationUri"] == "hosted", final["ConfigurationLocationUri"]
    assert final["Description"] == "sim2real-behav eventlog probe", final["Description"]
    # VersionLabel is echoed onto the deployment from the hosted version it deployed.
    assert final["VersionLabel"] == version_label, (
        f"the deployment must carry the deployed hosted version's label; got "
        f"{final.get('VersionLabel')!r}"
    )

    # --- Timestamps bound the run and are ordered.
    assert "StartedAt" in final and "CompletedAt" in final, sorted(final)
    assert _epoch(final["StartedAt"]) <= _epoch(final["CompletedAt"]), (
        f"StartedAt {final['StartedAt']!r} must not follow CompletedAt "
        f"{final['CompletedAt']!r}"
    )

    # --- AppliedExtensions is a real (here empty) list, not a missing key or a null.
    applied = final.get("AppliedExtensions", [])
    assert isinstance(applied, list), f"AppliedExtensions must be a list, got {applied!r}"
    assert applied == [], (
        f"no extension is associated with this application, so AppliedExtensions must be "
        f"empty; got {applied!r}"
    )

    # --- The event log itself.
    log = final["EventLog"]
    assert isinstance(log, list) and log, (
        f"EventLog must be a non-empty list for a completed deployment; got {log!r}"
    )
    kinds = [e["EventType"] for e in log]
    unmodeled = [k for k in kinds if k not in _EVENT_TYPES]
    assert not unmodeled, (
        f"EventLog contains EventType values outside the modeled enum: {unmodeled} "
        f"(modeled: {sorted(_EVENT_TYPES)})"
    )
    assert "DEPLOYMENT_STARTED" in kinds, kinds
    assert "DEPLOYMENT_COMPLETED" in kinds, kinds
    for event in log:
        assert event["TriggeredBy"] in _TRIGGERED_BY, (
            f"TriggeredBy {event['TriggeredBy']!r} is outside the modeled enum "
            f"{sorted(_TRIGGERED_BY)}"
        )
        assert "OccurredAt" in event, event
        assert event.get("Description"), (
            f"every deployment event carries a human-readable Description; got {event!r}"
        )

    # AppConfig returns the log newest-first; the order is pinned, not tested as a set.
    assert kinds[0] == "DEPLOYMENT_COMPLETED", (
        f"EventLog must be newest-first: expected DEPLOYMENT_COMPLETED at index 0, got "
        f"{kinds[0]!r} (full order: {kinds})"
    )
    assert kinds[-1] == "DEPLOYMENT_STARTED", (
        f"EventLog must be newest-first: expected DEPLOYMENT_STARTED last, got "
        f"{kinds[-1]!r} (full order: {kinds})"
    )
    stamps = [_epoch(e["OccurredAt"]) for e in log]
    assert stamps == sorted(stamps, reverse=True), (
        f"EventLog OccurredAt must be monotonically non-increasing newest-first; got "
        f"{stamps}"
    )
    assert _epoch(final["StartedAt"]) <= stamps[-1] + 1.0, (
        f"the earliest event ({stamps[-1]}) must not precede StartedAt "
        f"({_epoch(final['StartedAt'])})"
    )

    # --- ListDeployments' summary must agree with GetDeployment.
    summaries = ac.list_deployments(ApplicationId=app_id, EnvironmentId=env_id)["Items"]
    assert len(summaries) == 1, summaries
    assert summaries[0]["DeploymentNumber"] == dep_num, summaries[0]
    assert summaries[0]["State"] == "COMPLETE", summaries[0]
    assert summaries[0]["PercentageComplete"] == 100.0, summaries[0]
    assert summaries[0]["GrowthType"] == "LINEAR", summaries[0]
    assert summaries[0]["VersionLabel"] == version_label, summaries[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
