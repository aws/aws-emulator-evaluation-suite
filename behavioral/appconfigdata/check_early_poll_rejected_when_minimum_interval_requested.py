"""early-poll-rejected-when-minimum-interval-requested."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "early-poll-rejected-when-minimum-interval-requested"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfigdata']

_TAGS = {"sim2real:managed": "true", "sim2real": "early-poll-rejected-when-minimum-interval-requested"}

# AppConfig teardown order matters: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile is refused while any hosted
# configuration version survives, so the purge runs bottom-up.

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up; raise if it cannot finish."""
    try:
        environments = _items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        deadline = time.monotonic() + timeout_s
        for dep in _items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
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
                if exc.response["Error"]["Code"] not in (
                    "BadRequestException", "ResourceNotFoundException",
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
    for profile in _items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _items(
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
    for env in _items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=120):
    """Start a deployment and poll GetDeployment until it is COMPLETE.

    StartConfigurationSession is refused (ResourceNotFoundException) until a deployment completes.
    """
    number = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    final = None
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=number
        )
        if final.get("State") in _DEPLOYMENT_TERMINAL:
            assert final["State"] == "COMPLETE", (
                f"deployment {number} settled at {final['State']!r}, expected 'COMPLETE'"
            )
            return final
        time.sleep(1.0)
    raise AssertionError(
        f"deployment {number} never reached a terminal state within {timeout_s}s; "
        f"last read was {final!r}"
    )


def _error_response(fn):
    """The full botocore error response for a call that must fail; raise on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"the call was expected to be REJECTED but SUCCEEDED, returning {result!r}"
    )


MIN_POLL_INTERVAL = 60


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Polling the next token before a requested RequiredMinimumPollIntervalInSeconds is rejected
    with PollIntervalNotSatisfied; replaying the initial token, or an ungated session, is accepted.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-retrieving-the-configuration.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"gate":"open"}'

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
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    gated = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
        RequiredMinimumPollIntervalInSeconds=MIN_POLL_INTERVAL,
    )
    initial = gated["InitialConfigurationToken"]
    assert initial, "StartConfigurationSession returned no InitialConfigurationToken"

    first = acd.get_latest_configuration(ConfigurationToken=initial)
    assert first["Configuration"].read() == payload, (
        "the first poll of a gated session must still serve the deployed content"
    )
    assert first["NextPollIntervalInSeconds"] == MIN_POLL_INTERVAL, (
        f"NextPollIntervalInSeconds was {first['NextPollIntervalInSeconds']!r}, expected the "
        f"requested minimum {MIN_POLL_INTERVAL}"
    )
    next_token = first["NextPollConfigurationToken"]
    assert next_token and next_token != initial, (
        f"the first poll must hand back a NEW next-poll token; got {next_token!r} against an "
        f"initial token of the same value"
    )

    early = _error_response(lambda: acd.get_latest_configuration(ConfigurationToken=next_token))
    assert early["Error"]["Code"] == "BadRequestException", (
        f"an early poll must be rejected BadRequestException, got "
        f"{early['Error']['Code']!r} ({early['Error'].get('Message')!r})"
    )
    assert early["Error"]["Message"] == "Request too early", (
        f'expected the exact BadRequestException message AWS returns, got {early["Error"]["Message"]!r}'
    )
    assert early["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"BadRequestException must be HTTP 400, got "
        f"{early['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert early.get("Reason") == "InvalidParameters", (
        f"Reason was {early.get('Reason')!r}, expected 'InvalidParameters' -- the only value the "
        f"BadRequestReason enum declares"
    )
    problem = (
        early.get("Details", {}).get("InvalidParameters", {})
        .get("ConfigurationToken", {}).get("Problem")
    )
    assert problem == "PollIntervalNotSatisfied", (
        f"Details.InvalidParameters.ConfigurationToken.Problem was {problem!r}, expected "
        f"'PollIntervalNotSatisfied'. An emulator that rejects with a bare BadRequestException "
        f"and no Details gives a client no way to distinguish 'too early' (retry later) from "
        f"'corrupted' (restart the session)"
    )

    # A rejected poll does not advance the chain, so the same token stays the one to present later.
    assert "Configuration" not in early, (
        f"a rejected poll must not deliver configuration; response carried "
        f"{sorted(k for k in early if k != 'ResponseMetadata')!r}"
    )
    assert "NextPollConfigurationToken" not in early, (
        "a rejected poll must not issue a next-poll token, or the client's chain forks"
    )

    # The interval binds the next-poll token, not the session.
    replayed = acd.get_latest_configuration(ConfigurationToken=initial)
    assert replayed["Configuration"].read() == payload, (
        "re-presenting the initial token of a gated session must still serve the content -- the "
        "poll interval is not a session-wide lock"
    )

    # Without a requested minimum the advertised NextPollIntervalInSeconds is not enforced.
    ungated = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
    )
    ungated_first = acd.get_latest_configuration(
        ConfigurationToken=ungated["InitialConfigurationToken"]
    )
    assert ungated_first["Configuration"].read() == payload, (
        "the first poll of an ungated session must serve the deployed content"
    )
    ungated_second = acd.get_latest_configuration(
        ConfigurationToken=ungated_first["NextPollConfigurationToken"]
    )
    # Read the StreamingBody ONCE: a second .read() on a consumed body returns b'' and would
    # make the failure message below report emptiness whatever the service actually sent.
    unchanged_body = ungated_second["Configuration"].read()
    assert unchanged_body == b"", (
        f"an immediate second poll on an UNGATED session must be accepted and report 'unchanged' "
        f"with an empty payload; got {len(unchanged_body)} bytes ({unchanged_body[:64]!r})"
    )
    assert ungated_second["NextPollConfigurationToken"], (
        "an accepted unchanged poll must still advance the chain"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
