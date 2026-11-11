"""get-latest-configuration-returns-empty-when-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

import time

from behavioral_harness import tags

CHECK = "get-latest-configuration-returns-empty-when-unchanged"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfig']

# StartConfigurationSession.RequiredMinimumPollIntervalInSeconds: integer, min 15, max 86400.
# 15 is the modeled floor, chosen to keep wall clock as low as the contract permits.
MIN_POLL_INTERVAL = 15

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-latest-configuration-empty"}

# ===== helpers =====
# _deploy_and_wait_complete and _setup_deployed_config are deliberately strict: (1) the terminal
# predicate asserts State == "COMPLETE" instead of accepting the tolerant tuple ("COMPLETE",
# "ROLLED_BACK", "REVERTED") as "setup succeeded" — a rolled-back deployment is a broken
# precondition here, not a pass; (2) _poll_until is bounded and reports the last observation.


# AppConfig teardown ORDER is load-bearing: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile is refused while any hosted
# configuration version survives. A bare DeleteApplication teardown raises BadRequestException, and
# because the runner swallows teardown exceptions the application tree would leak while the check
# passed. Bottom-up is the only order AppConfig accepts.

def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Teardown reads every page, not just the first: AppConfig refuses a parent delete while any child
    survives, so a first-page-only purge would leak the tree.
    """
    return [item for page in pages for item in page.get("Items", [])]


_PURGE_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_PURGE_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up.

    Raises rather than leaking quietly: a purge that cannot finish is a real failure, even though
    the runner will swallow it.
    """
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(
                ApplicationId=app_id,
            )
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    # An environment mid-deployment is undeletable, so stop what is in flight and wait it out.
    for env in environments:
        env_id = env["Id"]
        # Per environment, NOT one budget for the whole purge: a shared deadline that earlier
        # environments had already spent left the wait loop below never entering its body, so
        # `state` stayed None and the `else` raised "never left None during cleanup" for a
        # perfectly deletable environment -- aborting teardown before a single delete ran.
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id,
                EnvironmentId=env_id,
            )
        ):
            if dep.get("State") in _PURGE_DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException", "ResourceNotFoundException",
                ):
                    raise
        state = None
        while time.monotonic() < deadline:
            state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
            if state not in _PURGE_ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(
                f"environment {env_id} never left {state!r} during cleanup"
            )
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
        ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, DeletionProtectionCheck="BYPASS"
        )
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _poll_until(probe, predicate, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, profile_id, version, timeout_s=90):
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]
    final = _poll_until(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        ),
        lambda d: d.get("State") in ("COMPLETE", "ROLLED_BACK", "REVERTED"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"deployment {dep_num} reaching a terminal state",
    )
    assert final["State"] == "COMPLETE", (
        f"setup precondition: deployment {dep_num} must reach COMPLETE, ended {final['State']!r}"
    )
    return dep_num


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a poll has served the current configuration, the next poll returns an EMPTY
    Configuration with a fresh NextPollConfigurationToken (AppConfig's "nothing changed" signal),
    and a later deployment makes the payload non-empty again."""
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    v1_payload = b'{"flag":"v1"}'
    v2_payload = b'{"flag":"v2"}'

    app_id = ac.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
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

    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v1_payload,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v1)

    # --- Open a session at the modeled minimum poll interval.
    session = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
        RequiredMinimumPollIntervalInSeconds=MIN_POLL_INTERVAL,
    )
    token = session["InitialConfigurationToken"]
    assert token, "StartConfigurationSession must return an InitialConfigurationToken"

    # --- First poll: the deployed content, plus the interval the service wants us to respect.
    first = _poll_until(
        lambda: acd.get_latest_configuration(ConfigurationToken=token),
        lambda r: r["Configuration"].read() == v1_payload,
        timeout_s=60,
        interval_s=2.0,
        description="the initial token serving the deployed v1 content",
    )
    interval = first["NextPollIntervalInSeconds"]
    assert interval >= MIN_POLL_INTERVAL, (
        f"NextPollIntervalInSeconds must be at least the requested minimum "
        f"{MIN_POLL_INTERVAL}, got {interval!r}"
    )
    next_token = first["NextPollConfigurationToken"]
    assert next_token, "a poll that served content must hand back a next-poll token"
    assert next_token != token, (
        "the next-poll token must differ from the initial token — an emulator that echoes the "
        "same token back has no notion of poll position, which is what the empty-payload "
        "signal below depends on"
    )

    # --- Wait out the interval the SERVICE asked for as a bounded retry, never a blind sleep:
    # presenting next_token before NextPollIntervalInSeconds has elapsed is refused with
    # BadRequestException, so retry on that specific refusal until the service itself accepts the
    # call, rather than trusting a canned duration to be long enough.
    unchanged = None
    wait_deadline = time.monotonic() + interval + 30
    while time.monotonic() < wait_deadline:
        try:
            unchanged = acd.get_latest_configuration(ConfigurationToken=next_token)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            time.sleep(2.0)
    assert unchanged is not None, (
        f"next_token was still refused after waiting {interval + 30}s for the service's own "
        f"NextPollIntervalInSeconds to elapse"
    )

    # --- Second poll with the next-poll token: nothing has changed, so the payload is EMPTY.
    body = unchanged["Configuration"].read()
    assert body == b"", (
        f"nothing was deployed between the two polls, so GetLatestConfiguration must return an "
        f"EMPTY Configuration payload; got {len(body)} bytes ({body[:64]!r}). An emulator that "
        f"re-serves the full configuration on every poll makes every AppConfig client believe "
        f"the configuration changed on every poll."
    )
    # ContentType is deliberately NOT asserted on the empty response: AWS documents the payload as
    # empty when unchanged but does not state whether ContentType is omitted or echoed.
    second_token = unchanged["NextPollConfigurationToken"]
    assert second_token, (
        "an empty (unchanged) response must STILL return a NextPollConfigurationToken — without "
        "one the client's polling loop terminates and it never sees future deployments"
    )
    assert second_token != next_token, (
        "the poll token must advance even on an unchanged response"
    )
    assert unchanged["NextPollIntervalInSeconds"] >= MIN_POLL_INTERVAL, (
        unchanged["NextPollIntervalInSeconds"]
    )

    # --- Control: deploy v2, then the same polling loop must produce non-empty content again,
    # proving the emptiness above was the unchanged-signal and not a dead data plane.
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v2_payload,
        ContentType="application/json",
    )["VersionNumber"]
    assert v2 == v1 + 1, (v1, v2)
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v2)

    chain_token = second_token
    served = None
    left = ctx.time_left()
    deadline = time.monotonic() + (120 if left is None else max(1.0, min(120, left - 5.0)))
    while time.monotonic() < deadline:
        time.sleep(2.0)
        try:
            response = acd.get_latest_configuration(ConfigurationToken=chain_token)
        except ClientError as exc:
            # A poll before NextPollIntervalInSeconds has elapsed is refused: retry it.
            if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            continue
        chain_token = response["NextPollConfigurationToken"]
        payload = response["Configuration"].read()
        if payload:
            served = payload
            break
    assert served == v2_payload, (
        f"after v2 was deployed, a poll must serve the new content; got {served!r} — if this is "
        f"None the data plane never surfaced the new deployment, and the empty payload asserted "
        f"above was not an unchanged-signal"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
