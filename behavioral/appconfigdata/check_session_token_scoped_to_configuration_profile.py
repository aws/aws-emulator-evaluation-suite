"""session-token-scoped-to-configuration-profile."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-token-scoped-to-configuration-profile"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfigdata']

# AppConfig refuses DeleteApplication while any environment or configuration profile survives, and
# DeleteConfigurationProfile while any hosted version survives, so teardown runs bottom-up.

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


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
        Tags={"sim2real-check": CHECK},
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
    """Two profiles in one application and environment, each deployed: each session's token serves
    only its own profile's bytes, never the other's.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload_a = b'{"profile":"alpha","flag":false}'
    payload_b = b'{"profile":"bravo","flag":true}'

    app_id = ac.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags={"sim2real-check": CHECK}
    )["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-"),
        Tags={"sim2real-check": CHECK},
    )["Id"]
    cp_a = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cpa-"),
        LocationUri="hosted",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    cp_b = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cpb-"),
        LocationUri="hosted",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    assert cp_a != cp_b, f"AppConfig reused a profile id: {cp_a!r}"
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    version_a = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_a,
        Content=payload_a,
        ContentType="application/json",
    )["VersionNumber"]
    version_b = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_b,
        Content=payload_b,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_a, version_a)
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_b, version_b)

    session_a = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_a,
    )["InitialConfigurationToken"]
    session_b = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_b,
    )["InitialConfigurationToken"]
    assert session_a != session_b, (
        "two sessions over different profiles must not share a token -- an identical token means "
        "the token carries no profile identity and the isolation below cannot hold"
    )

    served_a = acd.get_latest_configuration(ConfigurationToken=session_a)
    body_a = served_a["Configuration"].read()
    served_b = acd.get_latest_configuration(ConfigurationToken=session_b)
    body_b = served_b["Configuration"].read()

    assert body_a == payload_a, (
        f"profile A's token served {body_a!r}, expected {payload_a!r}"
        + (" -- it served profile B's configuration instead, so the session token is not scoped "
           "to its profile" if body_a == payload_b else "")
    )
    assert body_b == payload_b, (
        f"profile B's token served {body_b!r}, expected {payload_b!r}"
        + (" -- it served profile A's configuration instead, so the session token is not scoped "
           "to its profile" if body_b == payload_a else "")
    )

    # The chained tokens stay scoped too: rotation must not lose the profile binding.
    next_a = served_a["NextPollConfigurationToken"]
    next_b = served_b["NextPollConfigurationToken"]
    assert next_a != next_b, "chained tokens of two different sessions collided"

    # Re-presenting each initial token proves the binding is a property of the token and not of
    # call order -- B is polled first this time.
    again_b = acd.get_latest_configuration(ConfigurationToken=session_b)["Configuration"].read()
    again_a = acd.get_latest_configuration(ConfigurationToken=session_a)["Configuration"].read()
    assert (again_b, again_a) == (payload_b, payload_a), (
        f"polled in the reverse order, B served {again_b!r} and A served {again_a!r}; the "
        f"profile binding must live in the token, not in the order the client called"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
