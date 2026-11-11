"""stop-deployment-during-bake-reverts-to-the-previous-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-deployment-during-bake-reverts-to-the-previous-version"
GROUP = 'deployment'
SERVICES = ['appconfig']

# The bake window (FinalBakeTimeInMinutes) exists so a deployment at 100% can still be undone: a
# StopDeployment during BAKING ends ROLLED_BACK, logs TriggeredBy "USER" (not CLOUDWATCH_ALARM),
# keeps BAKE_TIME_STARTED in its EventLog, refuses a second stop with BadRequestException, and the
# data plane serves the previous configuration again. The synchronous StopDeployment response is
# only an acknowledgement, so the terminal state is polled. The 2-minute bake lets the stop land
# inside it.

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-stop-during-bake"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_TRIGGERED_BY = {"USER", "APPCONFIG", "CLOUDWATCH_ALARM", "INTERNAL_ERROR"}
# Long enough that the stop lands comfortably inside the window rather than racing its end.
_BAKE_MINUTES = 2
_POLL_INTERVAL_S = 3.0
# Named so the runner reads it as a declared deadline.
_STOP_BUDGET_S = 600
_ROLLBACK_TIMEOUT_S = 300


# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


def _error(fn):
    """Return the botocore Error (Code and Message) if fn() raises ClientError.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator that accepts
    input real AWS refuses is the strongest signal available, and returning "" would turn it into
    an error-code mismatch that reads like a naming difference.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        "the call under test SUCCEEDED where real AWS refuses it — this is an "
        "over-permissiveness failure, not an error-code mismatch"
    )


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


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll FRESH configuration sessions until one is served exactly `expect`; return the last
    payload seen either way.

    A bounded poll on an observable condition, not a sleep standing in for one. Each attempt opens a
    NEW session rather than chaining next-poll tokens, because a next-poll token presented before
    the session's own NextPollIntervalInSeconds is refused outright. The caller still asserts on the
    returned value, so bytes that never become `expect` fail the check with what was actually
    served; this loop can only remove the race, never an assertion.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        body = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
        if body == expect or time.monotonic() >= deadline:
            return body
        time.sleep(3.0)


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
    return dep_num


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StopDeployment issued while a fully-grown deployment is BAKING ends it ROLLED_BACK with
    TriggeredBy "USER" and the data plane serves the previous version again: the bake window is
    where a complete rollout can still be undone.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    # No Monitors: any rollback observed here must be attributable to the StopDeployment call, not
    # to an alarm. That is the difference between this check and the appconfig__cloudwatch sibling.
    environment = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert environment.get("Monitors", []) == [], (
        f"this check needs an UNMONITORED environment so the rollback can only come from the "
        f"caller; got {environment.get('Monitors')!r}"
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

    instant = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-instant-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=instant))
    baked = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-baked-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=_BAKE_MINUTES,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=baked))

    # --- BEAT 1, the barrier: version 1 is in service before anything is undone.
    _deploy_and_wait_complete(ac, app_id, env_id, instant, cp_id, v1)
    baseline = _sample_sessions(acd, app_id, env_id, cp_id, 3)
    assert set(baseline) == {v1_bytes}, (
        f"version 1 must be in service before the deployment under test; got "
        f"{sorted(set(baseline))!r}"
    )

    # --- BEAT 2: deploy version 2 with a real bake, and confirm it is FULLY in service while it
    #     bakes. Without this there is nothing for the stop to withdraw.
    dep2 = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=baked,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]
    baking = None
    deadline = time.monotonic() + _STOP_BUDGET_S
    while time.monotonic() < deadline:
        live = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )
        if live.get("State") == "BAKING":
            baking = live
            break
        assert live.get("State") not in _TERMINAL, (
            f"the deployment reached the terminal state {live.get('State')!r} before it ever "
            f"entered BAKING, so there was no bake window to stop it in; EventLog "
            f"{[e.get('EventType') for e in live.get('EventLog', [])]!r}"
        )
        time.sleep(_POLL_INTERVAL_S)
    assert baking is not None, (
        f"the deployment never entered BAKING within {_STOP_BUDGET_S}s, so the stop under test "
        f"could not be issued during a bake"
    )
    assert baking["PercentageComplete"] == 100.0, (
        f"a BAKING deployment has already reached 100% of targets; got "
        f"{baking['PercentageComplete']!r} — the point of this check is that a FULLY deployed "
        f"configuration is still withdrawable"
    )
    during_bake = _sample_sessions(acd, app_id, env_id, cp_id, 5)
    assert set(during_bake) == {v2_bytes}, (
        f"every session must be served version 2's exact bytes during the bake, so the stop has "
        f"something to undo; got {sorted(set(during_bake))!r}"
    )

    # --- BEAT 3, the act: stop it, from BAKING.
    acknowledged = ac.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
    )
    assert acknowledged["State"] in ("ROLLING_BACK", "ROLLED_BACK", "REVERTING", "REVERTED"), (
        f"StopDeployment acknowledges with a rollback or revert state; got "
        f"{acknowledged.get('State')!r}"
    )

    final = None
    deadline = time.monotonic() + _ROLLBACK_TIMEOUT_S
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )
        if final.get("State") in _TERMINAL:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert final is not None and final.get("State") in _TERMINAL, (
        f"the stopped deployment never reached a terminal state within {_ROLLBACK_TIMEOUT_S}s; "
        f"last state {(final or {}).get('State')!r}"
    )
    assert final["State"] == "ROLLED_BACK", (
        f"a deployment stopped during its bake must terminate ROLLED_BACK, got {final['State']!r} "
        f"— COMPLETE means the stop was ignored, which is over-permissiveness on AppConfig's last "
        f"chance to withdraw a release"
    )
    kinds = [e.get("EventType") for e in final.get("EventLog", [])]
    assert "BAKE_TIME_STARTED" in kinds, (
        f"the stopped deployment must show it had actually entered its bake window; EventLog "
        f"{kinds!r}"
    )
    assert "ROLLBACK_COMPLETED" in kinds, (
        f"the EventLog must record ROLLBACK_COMPLETED; got {kinds!r}"
    )
    assert "DEPLOYMENT_COMPLETED" not in kinds, (
        f"a rolled-back deployment must not also log DEPLOYMENT_COMPLETED; got {kinds!r}"
    )
    # MEASURED (real AWS, us-west-2): stopping a deployment that is BAKING at 100% jumps straight
    # to ROLLBACK_COMPLETED with no ROLLBACK_STARTED entry — there is no percentage left to unwind,
    # unlike a mid-rollout stop. ROLLBACK_STARTED is a real DeploymentEventType member (asserted
    # elsewhere, e.g. an extension-driven rollback), just not one this path emits.
    rollbacks = [e for e in final.get("EventLog", []) if e.get("EventType") == "ROLLBACK_COMPLETED"]
    assert rollbacks, f"ROLLBACK_COMPLETED must be present as an entry, not just a kind: {kinds!r}"
    for event in rollbacks:
        assert event["TriggeredBy"] in _TRIGGERED_BY, (
            f"TriggeredBy {event['TriggeredBy']!r} is outside the modeled enum "
            f"{sorted(_TRIGGERED_BY)}"
        )
        assert event["TriggeredBy"] == "USER", (
            f"this environment has no Monitors and nothing else asked for a rollback, so the "
            f"rollback must be attributed to the caller: TriggeredBy must be 'USER', got "
            f"{event['TriggeredBy']!r} — a target that reports CLOUDWATCH_ALARM here makes an "
            f"alarm-driven rollback and a user stop indistinguishable"
        )
    env_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
    assert env_state == "RolledBack", (
        f"a rolled-back environment reports the CamelCase State 'RolledBack' while GetDeployment "
        f"reports {final['State']!r} for the same event; got {env_state!r}"
    )

    # --- BEAT 4, effect absent AT THE DESTINATION: the previous configuration is back.
    restored = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert restored == v1_bytes, (
        f"after the stop the data plane must serve version 1's exact bytes again; got {restored!r}"
    )
    assert restored != v2_bytes, (
        "the data plane is still serving the withdrawn version, so the stop changed only the "
        "deployment record and not what clients receive"
    )
    confirm = _sample_sessions(acd, app_id, env_id, cp_id, 3)
    assert set(confirm) == {v1_bytes}, (
        f"the revert must be settled for EVERY session, not a transient in one: three fresh "
        f"sessions were served {sorted(set(confirm))!r}"
    )

    # --- BEAT 5: the terminal deployment is unusable. Stopping it again is refused.
    err = _error(
        lambda: ac.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"a rolled-back deployment is terminal, so a second StopDeployment must answer "
        f"BadRequestException; got {err['Code']!r}"
    )
    assert err["Message"] == (
        f"Deployment {dep2} for App {app_id} and Environment {env_id} cannot be stopped, "
        "it has a status of ROLLED_BACK."
    ), f"unexpected message: {err['Message']!r}"

    # --- BEAT 6, restore: the IDENTICAL version 2 deploys and is served, so the revert above was
    #     the stop and not a broken deployment path.
    _deploy_and_wait_complete(ac, app_id, env_id, instant, cp_id, v2)
    served_v2 = _serve_until(acd, app_id, env_id, cp_id, expect=v2_bytes)
    assert served_v2 == v2_bytes, (
        f"redeploying the IDENTICAL version 2 must reach the data plane; served {served_v2!r} — if "
        f"this fails the earlier revert cannot be attributed to StopDeployment"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
