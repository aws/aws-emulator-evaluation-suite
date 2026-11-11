"""session-accepts-names-as-identifiers."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-accepts-names-as-identifiers"
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartConfigurationSession accepts application, environment and profile names as well as ids,
    and both sessions serve the identical payload, as the model documents for all three members.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"identifier":"by-name"}'

    app_name = ctx.unique_name("sim2real-behav-app-")
    env_name = ctx.unique_name("sim2real-behav-env-")
    cp_name = ctx.unique_name("sim2real-behav-cp-")

    app_id = ac.create_application(Name=app_name, Tags={"sim2real": CHECK})["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=env_name, Tags={"sim2real": CHECK}
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=cp_name, LocationUri="hosted", Tags={"sim2real": CHECK}
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    # The ids and the names must be genuinely different strings, or nothing below discriminates.
    assert {app_id, env_id, cp_id}.isdisjoint({app_name, env_name, cp_name}), (
        f"an id equals a name ({app_id!r}/{app_name!r}, {env_id!r}/{env_name!r}, "
        f"{cp_id!r}/{cp_name!r}); the name form cannot be distinguished from the id form"
    )

    by_id = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
    )["InitialConfigurationToken"]
    by_name = acd.start_configuration_session(
        ApplicationIdentifier=app_name,
        EnvironmentIdentifier=env_name,
        ConfigurationProfileIdentifier=cp_name,
    )["InitialConfigurationToken"]
    assert by_name, "the name form returned no InitialConfigurationToken"
    assert by_name != by_id, (
        "two StartConfigurationSession calls must mint two distinct tokens even when they name "
        "the same configuration -- a session is per-call state, not a per-resource singleton"
    )

    served_by_name = acd.get_latest_configuration(ConfigurationToken=by_name)
    name_body = served_by_name["Configuration"].read()
    served_by_id = acd.get_latest_configuration(ConfigurationToken=by_id)
    id_body = served_by_id["Configuration"].read()

    assert name_body == payload, (
        f"the name-resolved session served {name_body!r}, expected {payload!r}"
    )
    assert id_body == name_body, (
        f"the id form served {id_body!r} and the name form {name_body!r}; both name the same "
        f"configuration, so they must resolve to the same bytes"
    )
    assert served_by_name["ContentType"] == served_by_id["ContentType"] == "application/json", (
        f"ContentType diverged between the two forms: {served_by_name.get('ContentType')!r} vs "
        f"{served_by_id.get('ContentType')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
