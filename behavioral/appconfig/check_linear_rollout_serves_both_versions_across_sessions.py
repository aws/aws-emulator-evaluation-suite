"""linear-rollout-serves-both-versions-across-sessions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "linear-rollout-serves-both-versions-across-sessions"
GROUP = 'deployment'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-linear-rollout"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_GROWTH_FACTOR = 25
_EXPECTED_STEPS = 100 // _GROWTH_FACTOR
# Named so the runner reads it as a declared deadline: it only recognises a name
# ending in timeout_s/deadline_s/budget_s/wait_s, so an honestly-named budget is what earns this
# suite the 1800s ceiling instead of the 300s light one.
_ROLLOUT_TIMEOUT_S = 900
_CONVERGE_TIMEOUT_S = 300

# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


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


# timing:real-time — schedule: 240 s https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A LINEAR strategy with GrowthFactor=25 advances through exactly four percentage steps, and
    mid-rollout concurrent sessions are split between the old and the new version's exact bytes,
    never a blend: GrowthFactor gates what the data plane serves, not an instant flip.
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
        DeploymentDurationInMinutes=4,
        GrowthFactor=_GROWTH_FACTOR,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=linear))

    _deploy_and_wait_complete(ac, app_id, env_id, ds_id=instant, cp_id=cp_id, version=v1)
    baseline = _sample_sessions(acd, app_id, env_id, cp_id, 5)
    assert set(baseline) == {v1_bytes}, (
        f"before the rollout every session must be served version 1's exact bytes; got "
        f"{sorted(set(baseline))!r}"
    )

    # --- The act: a 25%-step linear rollout of version 2.
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=linear,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]

    # Observe the rollout: at every mid-rollout tick, sample fresh sessions. The loop polls for
    # two observable conditions — both versions having been served, and the deployment reaching a
    # terminal state — and never sleeps for a fixed duration in place of either.
    mid_payloads = []
    percentages = []
    deadline = time.monotonic() + _ROLLOUT_TIMEOUT_S
    final = None
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        pct = final.get("PercentageComplete") or 0.0
        if not percentages or pct != percentages[-1]:
            percentages.append(pct)
        if final.get("State") in _TERMINAL:
            break
        if 0.0 < pct < 100.0:
            mid_payloads.extend(_sample_sessions(acd, app_id, env_id, cp_id, 4))
        time.sleep(4.0)
    assert final is not None and final.get("State") == "COMPLETE", (
        f"the linear rollout did not reach COMPLETE within {_ROLLOUT_TIMEOUT_S}s; last state "
        f"{(final or {}).get('State')!r} at {(final or {}).get('PercentageComplete')!r}%"
    )

    # --- No session was ever served a torn or blended document.
    torn = [p for p in mid_payloads if p not in (v1_bytes, v2_bytes)]
    assert not torn, (
        f"a mid-rollout session was served a payload that is neither hosted version: "
        f"{[p[:64] for p in torn]!r}"
    )

    # --- The rollout was genuinely PARTIAL: both versions were in service at the same time.
    assert v1_bytes in mid_payloads and v2_bytes in mid_payloads, (
        f"the rollout was not partial — across {len(mid_payloads)!r} mid-rollout sessions only "
        f"{sorted({p[:16] for p in mid_payloads})!r} was ever served, so the new version reached "
        f"either none or all of the fleet instead of a percentage of it"
    )

    # --- GrowthFactor gates the STEPS, and this is the observable that proves it. Real AWS logs
    #     one PERCENTAGE_UPDATED per step, so 100/GrowthFactor of them for a LINEAR strategy.
    steps = [e for e in final.get("EventLog", []) if e.get("EventType") == "PERCENTAGE_UPDATED"]
    assert len(steps) == _EXPECTED_STEPS, (
        f"a LINEAR strategy with GrowthFactor={_GROWTH_FACTOR} must advance in "
        f"{_EXPECTED_STEPS} steps, so the EventLog must carry {_EXPECTED_STEPS} "
        f"PERCENTAGE_UPDATED entries; got {len(steps)!r} out of event types "
        f"{[e.get('EventType') for e in final.get('EventLog', [])]!r}"
    )

    # --- PercentageComplete advanced monotonically through multiples of the growth factor.
    assert percentages == sorted(percentages), (
        f"PercentageComplete went backwards during the rollout: {percentages!r}"
    )
    off_grid = [p for p in percentages if p % _GROWTH_FACTOR != 0.0]
    assert not off_grid, (
        f"every observed PercentageComplete must be a multiple of GrowthFactor="
        f"{_GROWTH_FACTOR}; these were not: {off_grid!r} (whole sequence {percentages!r})"
    )
    assert percentages[-1] == 100.0, (
        f"the completed rollout must report PercentageComplete 100.0, got {percentages[-1]!r}"
    )

    # --- After completion the answer converges to one specific version for every session.
    #
    # Polled for unanimity rather than sampled once: the data plane can lag the deployment reaching
    # COMPLETE and PercentageComplete reaching 100 by a few seconds, so a sample taken the instant
    # the poll loop exits can still contain version 1. The assertion is unchanged by the loop — a fleet that never becomes unanimous still
    # fails, reporting what was actually served — and no claim is made about how fast it converges.
    settle_deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    settled = []
    while True:
        settled = _sample_sessions(acd, app_id, env_id, cp_id, 5)
        if set(settled) == {v2_bytes} or time.monotonic() >= settle_deadline:
            break
        time.sleep(5.0)
    assert set(settled) == {v2_bytes}, (
        f"after the rollout completed every session must be served version 2's exact bytes; got "
        f"{sorted(set(settled))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
