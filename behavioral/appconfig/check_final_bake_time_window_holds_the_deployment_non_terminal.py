"""final-bake-time-window-holds-the-deployment-non-terminal."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "final-bake-time-window-holds-the-deployment-non-terminal"
GROUP = 'deployment'
SERVICES = ['appconfig']

# FinalBakeTimeInMinutes is the time AppConfig monitors alarms AFTER the configuration reaches 100%
# of its targets, before the deployment is complete (CreateDeploymentStrategy). The window is
# bounded below by the declared minutes (server timestamps, and the client clock with one poll
# interval of slack) and above by a generous allowance, as AppConfig documents no scheduling
# granularity. With no Monitors on the environment nothing can roll the deployment back, so it must
# reach COMPLETE. BAKE_TIME_STARTED is logged once for a baked deployment and never for a bake-0
# one.

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-final-bake-window"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# 1 is the smallest bake that is still a window; the model's range is 0..1440.
_BAKE_MINUTES = 1
_POLL_INTERVAL_S = 3.0
# The only slack on the lower bound is the poll granularity: BAKING is first OBSERVED at most one
# poll interval after it began, so the client-measured window can be that much short.
_BAKE_SLACK_LOWER_S = _POLL_INTERVAL_S + 1.0
# A generous allowance, because AppConfig documents no scheduling granularity.
_BAKE_SLACK_UPPER_S = 300.0
# Named so the runner reads it as a declared deadline: it only recognises a name
# ending in timeout_s/deadline_s/budget_s/wait_s.
_BAKE_BUDGET_S = 600
_DEPLOY_TIMEOUT_S = 300


# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


def _epoch(value):
    """Seconds since the epoch for an AppConfig Iso8601DateTime, however botocore hands it over.

    Written out rather than assumed: the shape is a datetime under botocore's default parsing but a
    string under some transports, and an unconverted comparison would raise a TypeError that reads
    as an environment problem instead of asserting.
    """
    if isinstance(value, dt.datetime):
        return value.timestamp()
    if isinstance(value, str):
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    return float(value)


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=300):
    """Delete an application and everything beneath it, bottom-up. Raises rather than leaking."""
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        ):
            if dep.get("State") in _TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException",
                    "ResourceNotFoundException",
                ):
                    raise
        state = None
        while time.monotonic() < deadline:
            state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
            if state not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(f"environment {env_id} never left {state!r} during cleanup")
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            DeletionProtectionCheck="BYPASS",
        )
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _sample_sessions(acd, app_id, env_id, cp_id, n):
    """Open n independent sessions and return the payload each one is served."""
    out = []
    for _ in range(n):
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        out.append(acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read())
    return out


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=240):
    """Start a deployment and poll until COMPLETE. Deliberately NOT tolerant of ROLLED_BACK."""
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Tags=_TAGS,
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            break
        time.sleep(2.0)
    assert last is not None and last.get("State") == "COMPLETE", (
        f"deployment {dep_num} of version {version} did not reach COMPLETE within {timeout_s}s; "
        f"last state {(last or {}).get('State')!r}"
    )
    return last


# timing:real-time — cooldown: 60 s https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A 1-minute FinalBakeTimeInMinutes is a real window: the deployment reaches 100%, stays BAKING
    (serving the new configuration, not advanced by reads) for at least the declared minutes, then
    reports COMPLETE with one BAKE_TIME_STARTED event, which a bake-0 twin never logs.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'
    expected_window_s = 60.0 * _BAKE_MINUTES

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    # No Monitors: with nothing to consult there is nothing that can roll this deployment back, so
    # a non-COMPLETE outcome is a real failure rather than an alarm firing.
    environment = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert environment.get("Monitors", []) == [], (
        f"this check needs an UNMONITORED environment so the bake cannot end in a rollback; got "
        f"{environment.get('Monitors')!r}"
    )
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v1_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v2_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert (v1, v2) == (1, 2), f"hosted version numbering: got {v1!r}, {v2!r}"

    no_bake = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-nobake-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=no_bake))
    baked = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-baked-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=_BAKE_MINUTES,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=baked))
    stored = ac.get_deployment_strategy(DeploymentStrategyId=baked)
    assert stored["FinalBakeTimeInMinutes"] == _BAKE_MINUTES, (
        f"the strategy under test must carry a {_BAKE_MINUTES}-minute bake; got "
        f"{stored['FinalBakeTimeInMinutes']!r}"
    )

    # --- THE TWIN CONTROL, in the same run against the same application: bake 0 means no bake
    #     event at all. A target that fabricates a bake for every deployment fails here.
    unbaked = _deploy_and_wait_complete(ac, app_id, env_id, no_bake, cp_id, v1)
    unbaked_kinds = [e.get("EventType") for e in unbaked.get("EventLog", [])]
    # Asserted non-empty FIRST: without this the "no BAKE_TIME_STARTED" claim below is satisfied by
    # a target that returns no EventLog at all, which is the opposite of evidence.
    assert "DEPLOYMENT_COMPLETED" in unbaked_kinds and "DEPLOYMENT_STARTED" in unbaked_kinds, (
        f"the bake-0 twin must have a real event trail for its missing bake event to mean "
        f"anything; EventLog {unbaked_kinds!r}"
    )
    assert "BAKE_TIME_STARTED" not in unbaked_kinds, (
        f"a strategy with FinalBakeTimeInMinutes=0 has no bake window, so its EventLog must NOT "
        f"carry BAKE_TIME_STARTED; got {unbaked_kinds!r}"
    )
    assert unbaked["FinalBakeTimeInMinutes"] == 0, unbaked["FinalBakeTimeInMinutes"]
    baseline = _sample_sessions(acd, app_id, env_id, cp_id, 3)
    assert set(baseline) == {v1_bytes}, (
        f"before the baked rollout every session must be served version 1's exact bytes; got "
        f"{sorted(set(baseline))!r}"
    )

    # --- The act: deploy version 2 with a real bake window and time it.
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=baked,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]

    baking_observed_at = None
    baking_snapshot = None
    deadline = time.monotonic() + _BAKE_BUDGET_S
    while time.monotonic() < deadline:
        live = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if live.get("State") == "BAKING":
            baking_observed_at = time.monotonic()
            baking_snapshot = live
            break
        assert live.get("State") not in _TERMINAL, (
            f"the deployment reached the terminal state {live.get('State')!r} without ever "
            f"entering BAKING, so a {_BAKE_MINUTES}-minute FinalBakeTimeInMinutes cost it no time "
            f"at all; EventLog {[e.get('EventType') for e in live.get('EventLog', [])]!r}"
        )
        time.sleep(_POLL_INTERVAL_S)
    assert baking_snapshot is not None, (
        f"the deployment never entered BAKING within {_BAKE_BUDGET_S}s"
    )

    # --- The bake begins only after 100% of targets have it.
    assert baking_snapshot["PercentageComplete"] == 100.0, (
        f"the bake window opens AFTER the configuration has reached 100% of targets, so a BAKING "
        f"deployment must report PercentageComplete 100.0; got "
        f"{baking_snapshot['PercentageComplete']!r}"
    )
    baking_kinds = [e.get("EventType") for e in baking_snapshot.get("EventLog", [])]
    assert baking_kinds.count("BAKE_TIME_STARTED") == 1, (
        f"a baking deployment must have logged BAKE_TIME_STARTED exactly once; got {baking_kinds!r}"
    )

    # --- During the bake the NEW configuration is already what every session receives.
    during_bake = _sample_sessions(acd, app_id, env_id, cp_id, 5)
    assert set(during_bake) == {v2_bytes}, (
        f"a deployment in BAKING has already reached 100% of targets, so every session must be "
        f"served version 2's exact bytes during the bake; got {sorted(set(during_bake))!r}"
    )

    # --- Freeze detector: reading does not advance the state machine.
    frozen = [
        ac.get_deployment(ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num)
        for _ in range(3)
    ]
    frozen_states = [f["State"] for f in frozen]
    frozen_pcts = [f["PercentageComplete"] for f in frozen]
    assert frozen_states == ["BAKING"] * 3, (
        f"three consecutive GetDeployment reads during the bake must all report BAKING — reading "
        f"must not advance the deployment; got {frozen_states!r}"
    )
    assert frozen_pcts == [100.0] * 3, (
        f"PercentageComplete must not move during the bake; three reads gave {frozen_pcts!r}"
    )

    # --- Wait out the window and time it.
    final = None
    deadline = time.monotonic() + _BAKE_BUDGET_S
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if final.get("State") in _TERMINAL:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert final is not None and final.get("State") == "COMPLETE", (
        f"an UNMONITORED baked deployment has nothing that can roll it back, so it must reach "
        f"COMPLETE; last state {(final or {}).get('State')!r}"
    )
    client_measured_s = time.monotonic() - baking_observed_at

    # --- THE POINT, side one: the client-measured window is at least the declared one, with the
    #     poll granularity as the only slack.
    assert client_measured_s >= expected_window_s - _BAKE_SLACK_LOWER_S, (
        f"FinalBakeTimeInMinutes={_BAKE_MINUTES} must cost at least {expected_window_s}s of real "
        f"time between BAKING and COMPLETE; measured {client_measured_s:.1f}s (allowing "
        f"{_BAKE_SLACK_LOWER_S}s because BAKING is observed at most one poll interval late). A "
        f"target that treats the field as metadata completes in ~0s."
    )
    # --- Side two: the SERVER's own timestamps say the same thing, with no client clock involved.
    bake_events = [
        e for e in final.get("EventLog", []) if e.get("EventType") == "BAKE_TIME_STARTED"
    ]
    assert len(bake_events) == 1, (
        f"the completed deployment must carry exactly one BAKE_TIME_STARTED entry; got "
        f"{[e.get('EventType') for e in final.get('EventLog', [])]!r}"
    )
    bake_started_at = _epoch(bake_events[0]["OccurredAt"])
    completed_at = _epoch(final["CompletedAt"])
    server_measured_s = completed_at - bake_started_at
    assert server_measured_s >= expected_window_s, (
        f"AppConfig's own timestamps must bound the window: CompletedAt minus the "
        f"BAKE_TIME_STARTED OccurredAt is {server_measured_s:.1f}s, which is less than the "
        f"declared {expected_window_s}s"
    )
    assert server_measured_s < expected_window_s + _BAKE_SLACK_UPPER_S, (
        f"the bake must END on schedule too: the window ran {server_measured_s:.1f}s against a "
        f"declared {expected_window_s}s, past the {_BAKE_SLACK_UPPER_S}s scheduling allowance"
    )

    # --- The bake came after the rollout, not before it: ordered by the server's timestamps, not
    #     by index, so the assertion survives either EventLog direction.
    percentage_stamps = [
        _epoch(e["OccurredAt"])
        for e in final.get("EventLog", [])
        if e.get("EventType") == "PERCENTAGE_UPDATED"
    ]
    assert percentage_stamps, (
        f"a completed deployment must log at least one PERCENTAGE_UPDATED; got "
        f"{[e.get('EventType') for e in final.get('EventLog', [])]!r}"
    )
    assert bake_started_at >= max(percentage_stamps), (
        f"BAKE_TIME_STARTED must not precede the last PERCENTAGE_UPDATED — the bake opens after "
        f"the rollout finishes; bake at {bake_started_at}, last percentage step at "
        f"{max(percentage_stamps)}"
    )

    # --- Terminal read at the destination: the baked version is what clients are served, and the
    #     summary view agrees about the outcome.
    served = _sample_sessions(acd, app_id, env_id, cp_id, 3)
    assert set(served) == {v2_bytes}, (
        f"after the bake completed every session must be served version 2's exact bytes; got "
        f"{sorted(set(served))!r}"
    )
    summaries = {
        s["DeploymentNumber"]: s
        for s in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        )
    }
    assert summaries[dep_num]["State"] == "COMPLETE", (
        f"ListDeployments must agree with GetDeployment about the baked deployment's outcome; got "
        f"{summaries[dep_num]!r}"
    )
    assert summaries[dep_num]["FinalBakeTimeInMinutes"] == _BAKE_MINUTES, (
        f"the summary view must carry the bake the deployment actually served; got "
        f"{summaries[dep_num]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
