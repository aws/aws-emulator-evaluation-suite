"""start-deployment-latest-deployment-number-is-not-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-deployment-latest-deployment-number-is-not-enforced"
GROUP = 'deployment'
SERVICES = ['appconfig']

# StartDeployment.LatestDeploymentNumber is not enforced: calls with a stale value, 0, 999999999
# and the current value all succeed. AppConfig's other lock,
# `CreateHostedConfigurationVersion.LatestVersionNumber`, is enforced. botocore's appconfig service
# model never echoes LatestDeploymentNumber back on StartDeployment's or GetDeployment's output
# shape, consistent with a write-only, unvalidated field rather than an enforced optimistic lock.
# The Smithy model marks the member optional (`smithy.api#default: null`, not
# `smithy.api#required`), so its documented intent ("Use this value to ensure that the deployment
# starts from the expected state") is guidance for the caller, not a server-side precondition.
#
# A target that implements the documented "conditional write" semantics, the same shape as the
# hosted-config-version lock, REFUSES calls real AWS accepts: it is over-strict rather than
# over-permissive. This check asserts that `LatestDeploymentNumber` is accepted unconditionally,
# whether it names the current state, a value one deployment stale, the impossible past (0, after
# the environment has already advanced), or the impossible future (larger than any deployment
# number the environment could ever report).
#   - Every StartDeployment call below succeeds regardless of LatestDeploymentNumber's value, and
#     each creates a genuine new deployment that reaches the data plane: the field has no
#     observable effect on acceptance.
#   - Omitting LatestDeploymentNumber entirely is unconditional and always accepted; it is the
#     control.
#   - Every expected value is read back from the target (GetDeployment / ListDeployments), not
#     hard-coded.

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deployment-optimistic-lock"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


# Account-level deletion protection may be enabled, so DeleteEnvironment and
# DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=240):
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


def _wait_complete(ac, app_id, env_id, dep_num, timeout_s=180):
    """Poll GetDeployment until COMPLETE. Deliberately NOT tolerant of ROLLED_BACK; raises."""
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
        f"deployment {dep_num} did not reach COMPLETE within {timeout_s}s; last state "
        f"{(last or {}).get('State')!r}"
    )
    return last


def _deployment_numbers(ac, app_id, env_id):
    return sorted(
        d["DeploymentNumber"]
        for d in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        )
    )


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=180):
    """Poll FRESH configuration sessions until one is served exactly `expect`; return the last
    payload seen either way.

    A bounded poll on an observable condition, not a sleep standing in for one. Each attempt opens a
    NEW session rather than chaining next-poll tokens, because a next-poll token presented before
    the session's own NextPollIntervalInSeconds is refused outright. The caller still asserts on the
    returned value, so this loop can only remove the race, never an assertion.
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDeployment.LatestDeploymentNumber is not enforced as an optimistic lock: a current,
    stale, zero or future value each starts a genuine deployment that reaches COMPLETE and the data
    plane, and the environment history is exactly the returned deployment numbers in order."""
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'
    v3_bytes = b'{"tier":"three"}'
    v4_bytes = b'{"tier":"four"}'
    v5_bytes = b'{"tier":"five"}'

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
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    versions = [
        ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=payload,
            ContentType="application/json",
        )["VersionNumber"]
        for payload in (v1_bytes, v2_bytes, v3_bytes, v4_bytes, v5_bytes)
    ]
    assert versions == [1, 2, 3, 4, 5], f"hosted version numbering: got {versions!r}"
    v1, v2, v3, v4, v5 = versions

    def _deploy(config_version, latest_deployment_number):
        kwargs = dict(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(config_version),
            Tags=_TAGS,
        )
        if latest_deployment_number is not None:
            kwargs["LatestDeploymentNumber"] = latest_deployment_number
        dep_num = ac.start_deployment(**kwargs)["DeploymentNumber"]
        _wait_complete(ac, app_id, env_id, dep_num)
        return dep_num

    # --- BEAT 1, the control: an UNCONDITIONAL deployment (field omitted) succeeds and establishes
    #     the state later beats will deliberately misstate. Read back, never assumed.
    dep1 = _deploy(v1, None)
    served_v1 = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_v1 == v1_bytes, (
        f"beat 1 (unconditional): deployment {dep1} must reach the data plane; served {served_v1!r}"
    )
    latest_after_first = max(_deployment_numbers(ac, app_id, env_id))
    assert latest_after_first == dep1, (
        f"the environment's latest deployment must be the one just made ({dep1}); ListDeployments "
        f"reports {_deployment_numbers(ac, app_id, env_id)!r}"
    )

    # --- BEAT 2: naming the CORRECT current latest number is accepted too, so the field is not
    #     simply rejected on sight when it happens to match.
    dep2 = _deploy(v2, latest_after_first)
    served_v2 = _serve_until(acd, app_id, env_id, cp_id, expect=v2_bytes)
    assert served_v2 == v2_bytes, (
        f"beat 2 (correct precondition): deployment {dep2} must reach the data plane; served "
        f"{served_v2!r}"
    )
    latest_now = max(_deployment_numbers(ac, app_id, env_id))
    assert latest_now == dep2 and latest_now > latest_after_first, (
        f"the environment must have advanced past {latest_after_first} to {dep2}; ListDeployments "
        f"reports {_deployment_numbers(ac, app_id, env_id)!r}"
    )

    # --- BEAT 3, the core measured claim: LatestDeploymentNumber ONE DEPLOYMENT STALE — the exact
    #     value a real optimistic lock (like the sibling hosted-config-version lock) would refuse —
    #     is accepted anyway. `latest_after_first` was correct one deployment ago and is stale now.
    dep3 = _deploy(v3, latest_after_first)
    served_v3 = _serve_until(acd, app_id, env_id, cp_id, expect=v3_bytes)
    assert served_v3 == v3_bytes, (
        f"beat 3 (one-deployment-stale precondition {latest_after_first}): deployment {dep3} must "
        f"still reach the data plane; served {served_v3!r}"
    )
    assert dep3 > latest_now, (
        f"a StartDeployment naming a stale LatestDeploymentNumber must still create a genuine NEW "
        f"deployment past the environment's current latest ({latest_now}); got {dep3}"
    )

    # --- BEAT 4: LatestDeploymentNumber=0 — impossibly stale; no environment ever has a deployment
    #     numbered 0, and three real deployments already exist by this point — accepted anyway.
    dep4 = _deploy(v4, 0)
    served_v4 = _serve_until(acd, app_id, env_id, cp_id, expect=v4_bytes)
    assert served_v4 == v4_bytes, (
        f"beat 4 (LatestDeploymentNumber=0): deployment {dep4} must still reach the data plane; "
        f"served {served_v4!r}"
    )
    assert dep4 > dep3, (
        f"a StartDeployment naming LatestDeploymentNumber=0 must still create a genuine NEW "
        f"deployment past the environment's current latest ({dep3}); got {dep4}"
    )

    # --- BEAT 5: LatestDeploymentNumber=999999999 — impossibly future, larger than any deployment
    #     number this environment could ever have reported — is accepted anyway, by the same measure.
    dep5 = _deploy(v5, 999999999)
    served_v5 = _serve_until(acd, app_id, env_id, cp_id, expect=v5_bytes)
    assert served_v5 == v5_bytes, (
        f"beat 5 (impossible-future precondition): deployment {dep5} must still reach the data "
        f"plane; served {served_v5!r}"
    )
    assert dep5 > dep4, (
        f"a StartDeployment naming an impossible future LatestDeploymentNumber must still create a "
        f"genuine NEW deployment past the environment's current latest ({dep4}); got {dep5}"
    )

    # --- BEAT 6: across all five calls the environment recorded exactly one real, distinct
    #     deployment per call, in order — none of the "wrong" precondition values was silently
    #     absorbed, deduplicated, or otherwise treated differently from the correct one.
    history = _deployment_numbers(ac, app_id, env_id)
    assert history == [dep1, dep2, dep3, dep4, dep5], (
        f"five StartDeployment calls, none refused, must leave exactly five deployment records in "
        f"order regardless of each call's LatestDeploymentNumber value; ListDeployments reports "
        f"{history!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
