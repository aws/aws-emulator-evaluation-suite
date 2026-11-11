"""exponential-growth-type-advances-in-powers-of-the-growth-factor."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "exponential-growth-type-advances-in-powers-of-the-growth-factor"
GROUP = 'deployment'
SERVICES = ['appconfig']

# GrowthType=EXPONENTIAL advances a rollout through G*(2^N) percent, capped at 100 (documented for
# CreateDeploymentStrategy `growthType`), so GrowthFactor=10 steps 10 -> 20 -> 40 -> 80 -> 100, with
# one PERCENTAGE_UPDATED EventLog entry per step. Bucketing is per session, so a mid-rollout sample
# may be all-old: the "both versions served" leg accumulates across the rollout and asserts no
# proportion. The rollout keeps 4 minutes so AppConfig does not coalesce steps.

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-exponential-rollout"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# 10 is chosen because it makes the EXPONENTIAL and LINEAR step counts differ by a factor of two
# (5 versus 10), which is the whole discrimination. It is not a magic number: the expected grid is
# computed from it below.
_GROWTH_FACTOR = 10
_DURATION_MINUTES = 4
# Named so the runner reads it as a declared deadline: it only recognises a name
# ending in timeout_s/deadline_s/budget_s/wait_s, so an honestly-named budget is what earns this
# suite a raised ceiling instead of the 300s light one.
_ROLLOUT_TIMEOUT_S = 900
_CONVERGE_TIMEOUT_S = 300


# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


def _expected_exponential_grid(growth_factor):
    """The percentages G*(2^N) an EXPONENTIAL rollout must pass through, capped at 100.

    Computed, not tabulated: the expectation follows GrowthFactor rather than pinning literals, so
    changing the factor changes the expectation.
    """
    grid = []
    step = 0
    while True:
        percentage = float(growth_factor) * (2 ** step)
        if percentage >= 100.0:
            grid.append(100.0)
            return grid
        grid.append(percentage)
        step += 1


def _expected_linear_grid(growth_factor):
    """The percentages a LINEAR rollout with the same GrowthFactor would pass through.

    Used only to assert the two grids genuinely differ, so the check cannot silently degrade into
    one that a GrowthType-blind target also satisfies.
    """
    grid = []
    percentage = float(growth_factor)
    while percentage < 100.0:
        grid.append(percentage)
        percentage += float(growth_factor)
    grid.append(100.0)
    return grid


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
    """An EXPONENTIAL strategy with GrowthFactor=10 advances through the documented G*(2^N) grid
    (10, 20, 40, 80, 100: exactly five PERCENTAGE_UPDATED entries, half of LINEAR's ten) while the
    data plane serves both the old and the new configuration on the way.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'

    expected_grid = _expected_exponential_grid(_GROWTH_FACTOR)
    linear_grid = _expected_linear_grid(_GROWTH_FACTOR)
    # Guard the check's own premise: if the two algorithms predicted the same schedule there would
    # be nothing here to discriminate, and the assertions below would be vacuous.
    assert len(expected_grid) < len(linear_grid), (
        f"this check's premise is that EXPONENTIAL and LINEAR differ for GrowthFactor="
        f"{_GROWTH_FACTOR}: exponential grid {expected_grid!r} vs linear grid {linear_grid!r}"
    )
    assert expected_grid[-1] == 100.0 and expected_grid[0] == float(_GROWTH_FACTOR), (
        f"the derived grid must start at GrowthFactor and end at 100: {expected_grid!r}"
    )

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
    exponential = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-exponential-"),
        DeploymentDurationInMinutes=_DURATION_MINUTES,
        GrowthFactor=_GROWTH_FACTOR,
        GrowthType="EXPONENTIAL",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=exponential))

    _deploy_and_wait_complete(ac, app_id, env_id, ds_id=instant, cp_id=cp_id, version=v1)
    baseline = _sample_sessions(acd, app_id, env_id, cp_id, 5)
    assert set(baseline) == {v1_bytes}, (
        f"before the rollout every session must be served version 1's exact bytes; got "
        f"{sorted(set(baseline))!r}"
    )

    # --- The act: an EXPONENTIAL rollout of version 2.
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=exponential,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]

    # The deployment must have COPIED the growth settings, not merely referenced the strategy —
    # otherwise the assertions below are about a strategy the deployment might not be using.
    started = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
    )
    assert started["GrowthType"] == "EXPONENTIAL", (
        f"the deployment must carry the strategy's GrowthType; got {started.get('GrowthType')!r}"
    )
    assert started["GrowthFactor"] == float(_GROWTH_FACTOR), (
        f"the deployment must carry GrowthFactor={_GROWTH_FACTOR}; got "
        f"{started.get('GrowthFactor')!r}"
    )

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
        f"the exponential rollout did not reach COMPLETE within {_ROLLOUT_TIMEOUT_S}s; last state "
        f"{(final or {}).get('State')!r} at {(final or {}).get('PercentageComplete')!r}%"
    )

    # --- THE POINT: the step count is the one G*(2^N) predicts, and it is NOT the linear one.
    steps = [e for e in final.get("EventLog", []) if e.get("EventType") == "PERCENTAGE_UPDATED"]
    assert len(steps) == len(expected_grid), (
        f"an EXPONENTIAL strategy with GrowthFactor={_GROWTH_FACTOR} advances through the "
        f"percentages G*(2^N) = {expected_grid!r}, so the EventLog must carry "
        f"{len(expected_grid)} PERCENTAGE_UPDATED entries; got {len(steps)} out of event types "
        f"{[e.get('EventType') for e in final.get('EventLog', [])]!r}. A target that steps "
        f"LINEARLY with the same GrowthFactor would log {len(linear_grid)}."
    )
    assert len(steps) != len(linear_grid), (
        f"the observed step count {len(steps)} is the LINEAR count for GrowthFactor="
        f"{_GROWTH_FACTOR}, so GrowthType=EXPONENTIAL changed nothing about the rollout"
    )

    # --- Every percentage AppConfig reported is on the exponential grid, and the sequence advances.
    off_grid = [p for p in percentages if p not in ([0.0] + expected_grid)]
    assert not off_grid, (
        f"every observed PercentageComplete must lie on the exponential grid {expected_grid!r}; "
        f"these did not: {off_grid!r} (whole observed sequence {percentages!r})"
    )
    assert percentages == sorted(percentages), (
        f"PercentageComplete went backwards during the rollout: {percentages!r}"
    )
    assert percentages[-1] == 100.0, (
        f"the completed rollout must report PercentageComplete 100.0, got {percentages[-1]!r}"
    )

    # --- No session was ever served a torn or blended document.
    torn = [p for p in mid_payloads if p not in (v1_bytes, v2_bytes)]
    assert not torn, (
        f"a mid-rollout session was served a payload that is neither hosted version: "
        f"{[p[:64] for p in torn]!r}"
    )

    # --- The rollout was genuinely PARTIAL: both versions were in service at the same time. No
    #     proportion is asserted — bucketing is per session and independent.
    assert v1_bytes in mid_payloads and v2_bytes in mid_payloads, (
        f"the rollout was not partial — across {len(mid_payloads)!r} mid-rollout sessions only "
        f"{sorted({p[:16] for p in mid_payloads})!r} was ever served, so the new version reached "
        f"either none or all of the fleet instead of a percentage of it"
    )

    # --- After completion every session converges on version 2. Polled for unanimity because the
    #     data plane can lag the deployment reaching COMPLETE by a few seconds; the assertion is
    #     unchanged by the loop.
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
