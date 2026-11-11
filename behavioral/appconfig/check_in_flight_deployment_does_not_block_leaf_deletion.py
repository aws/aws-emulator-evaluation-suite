"""in-flight-deployment-does-not-block-leaf-deletion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "in-flight-deployment-does-not-block-leaf-deletion"
GROUP = 'overly-permissive'
SERVICES = ['appconfig']

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-in-flight-deployment-blocks-resource-deletion"}

# _drain_and_delete_app tears the tree down BOTTOM-UP (hosted versions, profiles, environments,
# application), because AppConfig gates DeleteApplication and DeleteConfigurationProfile on child
# existence (measured below), then polls to disappearance and raises on a deadline miss instead
# of swallowing every exception. It also tolerates the resources already being gone, since this
# check deletes most of them itself as part of the contract it grades.


def _error_pair(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"the call succeeded where AWS refuses it, returning {result!r}")


def _poll_until(probe, predicate, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Teardown reads every page, not just the first: AppConfig refuses a parent delete while any child
    survives, so a first-page-only purge would leak the tree.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _drain_and_delete_app(ac, app_id, timeout_s=180):
    """Stop in-flight deployments, delete the application's whole tree bottom-up, and
    confirm the application is gone. Raises rather than leaking silently."""
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
    for env in environments:
        env_id = env["Id"]
        # Per environment, NOT one budget for the whole purge: a shared deadline that earlier
        # environments had already spent left the wait loop below never entering its body, so its
        # `else` raised "never left ... during cleanup" for a perfectly deletable environment --
        # aborting teardown before a single delete ran.
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id,
                EnvironmentId=env_id,
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
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException", "ResourceNotFoundException",
                ):
                    raise
        while time.monotonic() < deadline:
            if ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get(
                "State"
            ) not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(
                f"environment {env_id} never left {_ENV_TRANSITIONAL} during cleanup"
            )
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(
            ApplicationId=app_id,
        )
    ):
        cp = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id,
                ConfigurationProfileId=cp,
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)
    # Its own budget as well, for the same reason: confirming the application is gone must not
    # inherit whatever the environment waits above happened to leave.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ac.get_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(1.0)
    raise AssertionError(f"application {app_id} still present after the cleanup deadline")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An in-flight AppConfig deployment gates only a second StartDeployment (ConflictException);
    it gates no deletion. DeleteHostedConfigurationVersion, DeleteConfigurationProfile and
    DeleteEnvironment succeed mid-deployment, while parent deletes are refused only on child existence."""
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    # A second, empty profile: it is the "unrelated leaf" control for the deletion legs and
    # the last child standing for the final DeleteApplication refusal.
    spare_cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-spare-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    # A long duration and bake time keep the deployment in flight for the refusal legs. The
    # deployment is stopped explicitly below; it is never allowed to run to term.
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=15,
        GrowthFactor=10,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=10,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"blocking":true}',
        ContentType="application/json",
    )["VersionNumber"]

    # --- Baseline: before any deployment, an environment IS deletable. Proving the positive
    # first is what makes each refusal below attributable to one named cause.
    throwaway_env = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-free-"), Tags=_TAGS
    )["Id"]
    throwaway_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=throwaway_env)[
        "State"
    ]
    assert throwaway_state == "ReadyForDeployment", (
        f"a never-deployed environment must start ReadyForDeployment, got {throwaway_state!r}"
    )
    ac.delete_environment(ApplicationId=app_id, EnvironmentId=throwaway_env)
    assert _error_pair(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=throwaway_env)
    ) == (
        "ResourceNotFoundException",
        f"Environment with Application Id {app_id} and Environment Id {throwaway_env} could not "
        f"be found for account {ctx.account}.",
    ), "a never-deployed environment must be freely deletable"

    # --- Break exactly one thing: put a deployment in flight.
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Tags=_TAGS,
    )["DeploymentNumber"]
    in_flight = _poll_until(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id),
        lambda e: e.get("State") == "Deploying",
        timeout_s=60,
        interval_s=2.0,
        description="environment entering the Deploying state",
    )
    # EnvironmentState is CamelCase on the wire even though the Smithy @enumValue is
    # SCREAMING_SNAKE.
    assert in_flight["State"] == "Deploying", in_flight["State"]
    assert (
        ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )["State"]
        not in _DEPLOYMENT_TERMINAL
    ), "the deployment must still be in flight for the refusal legs to mean anything"

    # --- The ONE thing an in-flight deployment does gate: another deployment. This is a 409,
    # not the 400 that every AppConfig structural refusal uses, so the code carries real
    # information about which kind of rule fired.
    start_code, start_msg = _error_pair(
        lambda: ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=spare_cp_id,
            ConfigurationVersion=str(version),
        )
    )
    assert start_code == "ConflictException", (
        f"a second StartDeployment on an environment that is Deploying must be refused with "
        f"ConflictException (409), got {start_code!r}; BadRequestException would conflate a "
        f"live-state conflict with AppConfig's structural 400s"
    )
    assert start_msg == (
        f"Environment {env_id} currently has a state of DEPLOYING. The current deployment "
        "must finish before a new deployment can be started."
    ), (
        f"the conflict must name the environment and its state; real AWS says "
        f'"Environment {env_id} currently has a state of DEPLOYING. The current deployment '
        f'must finish before a new deployment can be started." and this said {start_msg!r}'
    )
    # The casing asymmetry inside a single service: the ConflictException message renders the
    # environment state SCREAMING_SNAKE while GetEnvironment renders the same state CamelCase.
    assert (
        ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"] == "Deploying"
    ), "the refused StartDeployment must not disturb the environment state"
    # Effect absent: the refused start created no deployment record.
    listed = ac.list_deployments(ApplicationId=app_id, EnvironmentId=env_id).get("Items", [])
    assert [d["DeploymentNumber"] for d in listed] == [dep_num], (
        f"a refused StartDeployment must not create a deployment record; ListDeployments "
        f"shows {[d['DeploymentNumber'] for d in listed]}"
    )

    # --- Deletion is gated on CHILD EXISTENCE, not on deployment state. First direction: the
    # parent of a live child is undeletable, and the refusal names the child TYPE.
    app_code, app_msg = _error_pair(lambda: ac.delete_application(ApplicationId=app_id))
    assert app_code == "BadRequestException", (
        f"DeleteApplication must be refused while children exist, got {app_code!r}"
    )
    assert app_msg == (
        f"Cannot delete application {app_id}, because there are still environments existing under it."
    ), (
        f"the refusal must attribute itself to the surviving ENVIRONMENTS (the first child "
        f'type AppConfig checks); real AWS says "Cannot delete application {app_id}, because '
        f'there are still environments existing under it." and this said {app_msg!r}'
    )
    profile_code, profile_msg = _error_pair(
        lambda: ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        )
    )
    assert profile_code == "BadRequestException", (
        f"DeleteConfigurationProfile must be refused while hosted versions exist under it, "
        f"got {profile_code!r}"
    )
    assert profile_msg == (
        f"Cannot delete configuration profile {cp_id} because there are still hosted "
        "configuration versions existing under it."
    ), (
        f"the refusal must attribute itself to the surviving hosted versions, not to the "
        f"deployment; real AWS says \"Cannot delete configuration profile {cp_id} because "
        f'there are still hosted configuration versions existing under it." and this said '
        f"{profile_msg!r}"
    )
    # Effect absent: neither refusal touched anything.
    app_after_refusal = ac.get_application(ApplicationId=app_id)["Id"]
    assert app_after_refusal == app_id, (
        f"the refused DeleteApplication must leave the application readable, expected "
        f"{app_id!r}, got {app_after_refusal!r}"
    )
    assert sorted(e["Id"] for e in ac.list_environments(ApplicationId=app_id)["Items"]) == [
        env_id
    ], "the refused DeleteApplication must leave the environment listed"
    assert [
        v["VersionNumber"]
        for v in ac.list_hosted_configuration_versions(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        )["Items"]
    ] == [version], "the refused DeleteConfigurationProfile must leave the hosted version"

    # --- Second direction: a LEAF is deletable mid-deployment, even the exact leaf being
    # deployed.
    ac.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version
    )
    assert (
        ac.list_hosted_configuration_versions(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        ).get("Items", [])
        == []
    ), "the hosted version being deployed must really be gone"
    deploying_still = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
    )
    assert deploying_still["State"] not in _DEPLOYMENT_TERMINAL, (
        f"deleting the hosted version out from under a running deployment must not terminate "
        f"it; state is {deploying_still['State']!r}"
    )
    assert deploying_still["ConfigurationVersion"] == str(version), (
        f"the deployment record keeps naming the version it is deploying after that version "
        f"is deleted, got {deploying_still['ConfigurationVersion']!r}"
    )
    # Now the profile is itself a leaf, and it is deletable while it is being deployed.
    ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert _error_pair(
        lambda: ac.get_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        )
    ) == (
        "ResourceNotFoundException",
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id {cp_id} "
        f"could not be found for account {ctx.account}.",
    ), "the configuration profile being deployed must really be gone"
    orphaned = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
    )
    assert orphaned["State"] not in _DEPLOYMENT_TERMINAL, (
        f"deleting the profile being deployed must not terminate the deployment; state is "
        f"{orphaned['State']!r}"
    )
    assert orphaned["ConfigurationProfileId"] == cp_id, (
        f"the deployment record still names the deleted profile, got "
        f"{orphaned.get('ConfigurationProfileId')!r}"
    )
    assert (
        ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"] == "Deploying"
    ), "the environment is still Deploying a configuration profile that no longer exists"

    # --- The headline: the environment is deletable while it is being deployed to, and what
    # that leaves behind is asymmetric between the read paths and StopDeployment.
    ac.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    env_gone = (
        f"Environment with Application Id {app_id} and Environment Id {env_id} could not be "
        f"found for account {ctx.account}."
    )
    assert _error_pair(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    ) == ("ResourceNotFoundException", env_gone), (
        "DeleteEnvironment on an environment in Deploying is ACCEPTED by real AWS and the "
        "environment is gone immediately; an emulator that refuses it is stricter than AWS "
        "and an emulator that accepts it but keeps the environment readable is looser"
    )
    get_dep_code, get_dep_msg = _error_pair(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
    )
    assert get_dep_code == "ResourceNotFoundException", (
        f"GetDeployment for the orphaned deployment must 404 once its environment is gone, "
        f"got {get_dep_code!r}"
    )
    assert get_dep_msg == (
        f"Deployment with Application Id {app_id}, Environment Id {env_id}, and deploymentNumber "
        f"{dep_num} could not be found for account {ctx.account}."
    ), (
        f"the 404 is reported against the DEPLOYMENT, naming its number; real AWS says "
        f'"Deployment with Application Id ..., Environment Id ..., and deploymentNumber '
        f'{dep_num} could not be found ..." and this said {get_dep_msg!r}'
    )
    list_dep_code, list_dep_msg = _error_pair(
        lambda: ac.list_deployments(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert list_dep_code == "ResourceNotFoundException", (
        f"ListDeployments for a deleted environment must RAISE, not return an empty page, "
        f"got {list_dep_code!r} — an emulator that answers Items=[] here is the common shortcut"
    )
    assert list_dep_msg == env_gone, (
        f"the list 404 is reported against the ENVIRONMENT, not the deployment; got "
        f"{list_dep_msg!r}"
    )
    # ...and yet the deployment is still there, and still mutable, through StopDeployment.
    stopped = ac.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
    )
    assert stopped["State"] == "ROLLED_BACK", (
        f"StopDeployment on the orphaned deployment SUCCEEDS on real AWS and returns it "
        f"ROLLED_BACK, got {stopped['State']!r}: the record survives its environment for the "
        f"purposes of this operation while being unreadable through GetDeployment and "
        f"ListDeployments, which is the exact asymmetry an emulator modelling deletion as a "
        f"cascade cannot produce"
    )
    assert stopped["DeploymentNumber"] == dep_num, stopped["DeploymentNumber"]
    assert stopped["ConfigurationProfileId"] == cp_id, (
        f"the stopped deployment still names its deleted profile, got "
        f"{stopped.get('ConfigurationProfileId')!r}"
    )
    assert "ROLLBACK_COMPLETED" in [e["EventType"] for e in stopped.get("EventLog", [])], (
        f"the rollback must be recorded in the deployment's EventLog, got "
        f"{[e.get('EventType') for e in stopped.get('EventLog', [])]}"
    )
    assert ac.list_environments(ApplicationId=app_id).get("Items", []) == [], (
        "the deleted environment must disappear from the listing"
    )

    # --- Control: the child-existence rule is the only thing left gating the application, and
    # the refusal now names the OTHER child type. Clear it and the identical delete succeeds.
    app_code2, app_msg2 = _error_pair(lambda: ac.delete_application(ApplicationId=app_id))
    assert app_code2 == "BadRequestException", (
        f"with no environments but a surviving configuration profile, DeleteApplication must "
        f"still be refused, got {app_code2!r}"
    )
    assert app_msg2 == (
        f"Cannot delete application {app_id}, because there are still configuration profiles "
        "existing under it."
    ), (
        f"the refusal must now attribute itself to the surviving PROFILE rather than to an "
        f"environment; got {app_msg2!r}"
    )
    ac.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=spare_cp_id
    )
    ac.delete_application(ApplicationId=app_id)
    assert _error_pair(lambda: ac.get_application(ApplicationId=app_id)) == (
        "ResourceNotFoundException",
        f"Application with Id {app_id} could not be found for account {ctx.account}.",
    ), "with every child gone the identical DeleteApplication must succeed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
