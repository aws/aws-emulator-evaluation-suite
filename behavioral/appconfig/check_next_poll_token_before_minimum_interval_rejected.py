"""next-poll-token-before-minimum-interval-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "next-poll-token-before-minimum-interval-rejected"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-poll-interval"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# The AWS minimum for RequiredMinimumPollIntervalInSeconds; the interval must really elapse.
_REQUIRED_MINIMUM_POLL_S = 15
_ACCEPTANCE_TIMEOUT_S = 240
_EARLY_POLL_MESSAGE = "Request too early"

# Account-level AppConfig deletion protection may be enabled, so deletes pass
# DeletionProtectionCheck="BYPASS".


def _error(fn):
    """Return the botocore Error dict if fn() raises ClientError; raise on unexpected SUCCESS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        "the call under test SUCCEEDED where real AWS refuses it — this is an "
        "over-permissiveness failure, not an error-code mismatch"
    )


def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the run budget."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


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


# timing:real-time — lease: 10 s https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_appconfigdata_GetLatestConfiguration.html
@tags(
    "axis:rejection",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A NextPollConfigurationToken presented before NextPollIntervalInSeconds elapses is refused
    with BadRequestException "Request too early" and is not consumed: once the interval passes the
    same token returns the empty "unchanged" payload, and a fresh session is served immediately.

    Reference: https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_appconfigdata_GetLatestConfiguration.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"tier":"one"}'

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
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    # --- Full valid setup: a session that declares its own minimum poll interval, and a first
    #     poll that demonstrably WORKS. This successful call is the barrier: everything refused
    #     after it is refused for a reason other than "the configuration is not ready yet".
    session = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
        RequiredMinimumPollIntervalInSeconds=_REQUIRED_MINIMUM_POLL_S,
    )
    initial_token = session["InitialConfigurationToken"]
    first = None
    deadline = _deadline(ctx, _ACCEPTANCE_TIMEOUT_S)
    while time.monotonic() < deadline:
        first = acd.get_latest_configuration(ConfigurationToken=initial_token)
        if first["Configuration"].read() == payload:
            break
        time.sleep(2.0)
    assert first is not None, "the first poll never ran"
    interval = first["NextPollIntervalInSeconds"]
    assert interval >= _REQUIRED_MINIMUM_POLL_S, (
        f"the session must honour the requested minimum poll interval of "
        f"{_REQUIRED_MINIMUM_POLL_S}s; NextPollIntervalInSeconds was {interval!r}"
    )
    next_token = first["NextPollConfigurationToken"]
    assert next_token != initial_token, (
        f"GetLatestConfiguration must hand back a rotated NextPollConfigurationToken, got the "
        f"initial token again ({next_token[:16]!r}...)"
    )

    # --- Break exactly one thing: present that token immediately instead of waiting the interval.
    err = _error(lambda: acd.get_latest_configuration(ConfigurationToken=next_token))
    assert err["Code"] == "BadRequestException", (
        f"presenting a NextPollConfigurationToken before NextPollIntervalInSeconds has elapsed "
        f"must be refused with BadRequestException, got {err['Code']!r} — an emulator that treats a token "
        f"as a stateless lookup key serves the payload here and is over-permissive on the poll "
        f"rate contract"
    )

    assert err["Message"] == _EARLY_POLL_MESSAGE, f"unexpected message: {err['Message']!r}"

    # --- Effect absent, in the only form available: the refused call served no configuration and
    #     did not invalidate the session. Poll the SAME token until the interval has elapsed; it
    #     must then be accepted. If the refusal had consumed the token this loop would never end.
    accepted = None
    deadline = _deadline(ctx, _ACCEPTANCE_TIMEOUT_S)
    refusals = 0
    while time.monotonic() < deadline:
        try:
            accepted = acd.get_latest_configuration(ConfigurationToken=next_token)
            break
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "BadRequestException", (
                f"an early poll must be refused with BadRequestException, got "
                f"{exc.response['Error']['Code']!r}"
            )
            assert exc.response["Error"]["Message"] == _EARLY_POLL_MESSAGE, (
                f"unexpected early-poll message: {exc.response['Error']['Message']!r}"
            )
            refusals += 1
            time.sleep(2.0)
    assert accepted is not None, (
        f"the same NextPollConfigurationToken was still refused {refusals!r} times over "
        f"{_ACCEPTANCE_TIMEOUT_S}s — the too-early refusal consumed or invalidated the token "
        f"instead of merely rate-limiting it"
    )
    assert refusals >= 1, (
        "the token became acceptable without a single further refusal, so no rate limit was in "
        "force and the first refusal cannot have been about timing"
    )
    # The accepted poll returns the documented EMPTY payload: nothing has changed after the first
    # poll, which is how AppConfig says "no update" rather than resending the bytes. Read once —
    # a StreamingBody is consumed by the first read, so re-reading it inside an assert message
    # would report an empty body for every failure.
    accepted_body = accepted["Configuration"].read()
    assert accepted_body == b"", (
        f"an accepted poll on an unchanged configuration returns an empty payload; got "
        f"{accepted_body!r}"
    )
    assert accepted["NextPollConfigurationToken"] != next_token, (
        "the accepted poll must rotate the token again"
    )

    # --- The positive control, in the same file: a brand-new session against the same
    #     application/environment/profile is served the deployed bytes with no wait at all. The
    #     refusal above was about the poll rate of one session, not about this configuration.
    control_token = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
    )["InitialConfigurationToken"]
    control = acd.get_latest_configuration(ConfigurationToken=control_token)
    control_body = control["Configuration"].read()
    assert control_body == payload, (
        f"a fresh session must still be served the deployed bytes; got {control_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
