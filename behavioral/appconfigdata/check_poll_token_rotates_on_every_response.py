"""poll-token-rotates-on-every-response."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "poll-token-rotates-on-every-response"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfigdata']

# AppConfig refuses DeleteApplication while any environment or configuration profile survives, and
# DeleteConfigurationProfile while any hosted version survives, so teardown runs bottom-up.

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_TAGS = {"sim2real:managed": "true", "sim2real": "poll-token-rotates-on-every-response"}


def _items(pages):
    """Flatten an AppConfig paginator's pages into one list of items; every page is read so no
    child survives a parent delete.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and all its children bottom-up; raise if the purge cannot finish."""
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
        # Per environment, NOT one budget for the whole purge.
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
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=120):
    """Start a deployment and poll GetDeployment until it is COMPLETE.

    Polls an observable condition rather than sleeping: GetLatestConfiguration serves nothing at
    all until a deployment has completed (StartConfigurationSession itself is refused with
    ResourceNotFoundException), so the wait is the precondition of the whole check.
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each GetLatestConfiguration response returns a new poll token, consecutive tokens are all
    distinct, and the initial and every superseded token of the session still resolve.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"rotation":"probe"}'

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

    initial = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
    )["InitialConfigurationToken"]
    assert initial, "StartConfigurationSession returned no InitialConfigurationToken"

    # --- Four consecutive polls, chaining the token the service hands back each time.
    chain = [initial]
    bodies = []
    token = initial
    for hop in range(4):
        response = acd.get_latest_configuration(ConfigurationToken=token)
        bodies.append(response["Configuration"].read())
        issued = response["NextPollConfigurationToken"]
        assert issued, f"poll {hop} returned no NextPollConfigurationToken"
        assert issued != token, (
            f"poll {hop} echoed the token it was given back unchanged ({issued[:24]!r}...); every "
            f"response must mint a NEW token or the client can never advance its poll position"
        )
        chain.append(issued)
        token = issued

    assert len(set(chain)) == len(chain), (
        f"the 5 tokens of this session were not all distinct: {len(set(chain))} unique out of "
        f"{len(chain)}. A repeat means the service reissued a token it had already handed out"
    )
    assert bodies[0] == payload, (
        f"the first poll must serve the deployed content; got {bodies[0]!r}"
    )
    assert all(b == b"" for b in bodies[1:]), (
        f"nothing was deployed between the polls, so hops 1-3 must report unchanged with an "
        f"empty payload; got lengths {[len(b) for b in bodies[1:]]!r}"
    )

    # --- The invariant that separates rotation from single-use: an already-superseded token is
    #     still resolvable. chain[1] was consumed by hop 1 and superseded by chain[2].
    superseded = acd.get_latest_configuration(ConfigurationToken=chain[1])
    superseded["Configuration"].read()
    assert superseded["NextPollConfigurationToken"], (
        "re-presenting an already-superseded next-poll token must be accepted and must itself "
        "mint a token -- real AWS does not model the token as single-use, so an emulator that "
        "rejects it fails every client that retries a dropped poll"
    )
    assert superseded["NextPollConfigurationToken"] not in chain, (
        f"re-presenting a superseded token returned a token already seen in this session's "
        f"chain; rotation must be unconditional"
    )

    # --- Same for the INITIAL token, which is the one a client is most likely to resend.
    revisited = acd.get_latest_configuration(ConfigurationToken=initial)
    assert revisited["Configuration"].read() == payload, (
        "re-presenting the initial token must serve the content again: the initial token marks "
        "poll position zero, so from its perspective nothing has been seen yet"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
