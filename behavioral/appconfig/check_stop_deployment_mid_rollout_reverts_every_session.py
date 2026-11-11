"""stop-deployment-mid-rollout-reverts-every-session."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-deployment-mid-rollout-reverts-every-session"
GROUP = 'deployment'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-stop-mid-rollout"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_SAMPLE_WIDTH = 20
# Named so the runner reads it as a declared deadline: it only recognises a name
# ending in timeout_s/deadline_s/budget_s/wait_s.
_PARTIAL_ROLLOUT_TIMEOUT_S = 600
_CONVERGE_TIMEOUT_S = 300

# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


def _error(fn):
    """Call fn(); return its botocore Error (Code and Message). An unexpected SUCCESS raises,
    so an over-permissive target fails as a success rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


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
    for env in _purge_items(
        ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
    ):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


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
        f"deployment {dep_num} of version {version} did not reach COMPLETE within "
        f"{timeout_s}s; last state {(last or {}).get('State')!r}"
    )
    return dep_num


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


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """StopDeployment part way through a linear rollout is a withdrawal, not a freeze: it answers
    ROLLED_BACK, every fresh session is served the previous version's exact bytes again, and a
    second stop on the terminal deployment is refused with BadRequestException.
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
    linear = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-linear-"),
        DeploymentDurationInMinutes=5,
        GrowthFactor=20,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=linear))

    _deploy_and_wait_complete(ac, app_id, env_id, ds_id=instant, cp_id=cp_id, version=v1)

    # --- The precondition is an OBSERVED partial rollout, not a guessed one: poll until the same
    #     environment is demonstrably serving BOTH versions. Bucketing is per session and
    #     independent (measured), so a single sample can miss; the loop is the barrier.
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=linear,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]
    seen = set()
    pct_at_stop = None
    deadline = time.monotonic() + _PARTIAL_ROLLOUT_TIMEOUT_S
    while time.monotonic() < deadline:
        live = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        pct = live.get("PercentageComplete") or 0.0
        assert live.get("State") not in _TERMINAL, (
            f"the rollout reached {live.get('State')!r} at {pct!r}% before both versions were "
            f"ever observed in service; only {sorted(s[:16] for s in seen)!r} was seen, so there "
            f"was no partial state to stop"
        )
        if 0.0 < pct < 100.0:
            seen.update(_sample_sessions(acd, app_id, env_id, cp_id, _SAMPLE_WIDTH))
            if {v1_bytes, v2_bytes} <= seen:
                pct_at_stop = pct
                break
        time.sleep(3.0)
    assert pct_at_stop is not None, (
        f"never observed a genuinely partial rollout within {_PARTIAL_ROLLOUT_TIMEOUT_S}s; the "
        f"payloads seen were {sorted(s[:16] for s in seen)!r}"
    )
    assert 0.0 < pct_at_stop < 100.0, f"pct_at_stop is not mid-rollout: {pct_at_stop!r}"

    # --- Break the rollout with exactly one call, and read the SYNCHRONOUS answer.
    stop_resp = ac.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
    )
    assert stop_resp["State"] == "ROLLED_BACK", (
        f"StopDeployment on a mid-rollout deployment must answer State='ROLLED_BACK' "
        f"synchronously, got {stop_resp['State']!r} — there is no 'STOPPED' member in the "
        f"DeploymentState enum, and 'REVERTED' is the AllowRevert path on a COMPLETE deployment"
    )
    assert stop_resp["PercentageComplete"] == 0.0, (
        f"a rolled-back deployment reports PercentageComplete 0.0, not the percentage it had "
        f"reached; got {stop_resp['PercentageComplete']!r} (it was at {pct_at_stop!r}%)"
    )

    final = None
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if final.get("State") in _TERMINAL:
            break
        time.sleep(2.0)
    assert final is not None and final["State"] == "ROLLED_BACK", (
        f"the stopped deployment must settle on ROLLED_BACK, got {(final or {}).get('State')!r}"
    )
    assert any(e.get("EventType") == "ROLLBACK_COMPLETED" for e in final.get("EventLog", [])), (
        f"the EventLog must record ROLLBACK_COMPLETED for a user-requested stop; got "
        f"{[e.get('EventType') for e in final.get('EventLog', [])]!r}"
    )
    env_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
    assert env_state == "RolledBack", (
        f"a rolled-back environment reports the CamelCase State 'RolledBack', got {env_state!r} — "
        f"'ReadyForDeployment' would mean the emulator treats a stop as a completed deployment"
    )

    # --- THE point: the withdrawal reaches the data plane. Poll until a full width of fresh
    #     sessions is unanimously back on version 1, then require it to STAY that way.
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    payloads = []
    unanimous = False
    while time.monotonic() < deadline:
        payloads = _sample_sessions(acd, app_id, env_id, cp_id, _SAMPLE_WIDTH)
        torn = [p for p in payloads if p not in (v1_bytes, v2_bytes)]
        assert not torn, f"a post-stop session was served neither version: {[p[:64] for p in torn]!r}"
        if set(payloads) == {v1_bytes}:
            unanimous = True
            break
        time.sleep(5.0)
    assert unanimous, (
        f"after the rollback, {_SAMPLE_WIDTH} fresh sessions were still not unanimously served "
        f"version 1 within {_CONVERGE_TIMEOUT_S}s — the last sample held "
        f"{sorted(set(p[:16] for p in payloads))!r}, so the withdrawn version is still in service"
    )
    confirm = _sample_sessions(acd, app_id, env_id, cp_id, _SAMPLE_WIDTH)
    assert set(confirm) == {v1_bytes}, (
        f"the rollback is not settled: a second sample of {_SAMPLE_WIDTH} sessions held "
        f"{sorted(set(p[:16] for p in confirm))!r} rather than version 1 alone"
    )
    assert v2_bytes not in confirm, (
        "the data plane is still serving the rolled-back version to some sessions, so the stop "
        "froze the split instead of withdrawing it"
    )

    # --- A second stop on the terminal deployment is refused, and changes nothing.
    err = _error(
        lambda: ac.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"stopping an already-ROLLED_BACK deployment must be refused with BadRequestException, "
        f"got {err['Code']!r} — an emulator that accepts it is over-permissive on the deployment state "
        f"machine"
    )
    assert err["Message"] == (
        f"Deployment {dep_num} for App {app_id} and Environment {env_id} cannot be stopped, "
        "it has a status of ROLLED_BACK."
    ), f"unexpected message: {err['Message']!r}"
    assert (
        ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )["State"]
        == "ROLLED_BACK"
    ), "the refused second stop must leave the deployment ROLLED_BACK"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
