"""start-deployment-full-lifecycle-to-complete."""
from __future__ import annotations

from botocore.exceptions import ClientError

import time

from behavioral_harness import tags

CHECK = "start-deployment-full-lifecycle-to-complete"
GROUP = 'deployment'
SERVICES = ['appconfig']


# AppConfig teardown ORDER is load-bearing: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile is refused while any hosted
# configuration version survives. Bottom-up is the only order AppConfig accepts.

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

    Raises rather than leaking quietly: a purge that cannot finish is a real failure, reported in
    cleanup_detail.
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
        # Per environment, not one budget for the whole purge: each environment gets the full wait.
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
        # BYPASS: the account-level deletion protection refuses a profile/environment that was
        # read within the protection window, and this check reads it via GetLatestConfiguration.
        ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, DeletionProtectionCheck="BYPASS"
        )
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; RAISES on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A zero-duration deployment reaches COMPLETE and GetConfiguration serves its content."""
    ac = ctx.client("appconfig")
    resource_tags = {"sim2real-behav": "start-deployment-full-lifecycle-to-complete"}
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=resource_tags)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=resource_tags
    )
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-cp-"), LocationUri="hosted",
        Tags=resource_tags,
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=resource_tags,
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id)))

    payload = b'{"feature_x": "on"}'
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=payload, ContentType="application/json"
    )["VersionNumber"]

    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env["Id"],
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]
    final = _poll_until(
        lambda: ac.get_deployment(ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=dep_num),
        lambda d: d.get("State") in ("COMPLETE", "ROLLED_BACK", "REVERTED"),
        timeout_s=45,
        interval_s=1.0,
        description="deployment reaching a terminal state",
    )
    assert final["State"] == "COMPLETE", f"deployment did not complete: {final.get('State')}"
    assert final["PercentageComplete"] == 100, f"expected 100% complete, got {final.get('PercentageComplete')!r}"

    # Environment state is CamelCase ('ReadyForDeployment'), unlike DeploymentState
    # which is SCREAMING_SNAKE ('COMPLETE'). Verified against real AWS.
    env_after = _poll_until(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=env["Id"]),
        lambda e: e.get("State") == "ReadyForDeployment",
        timeout_s=60,
        interval_s=2.0,
        description="environment returning to ReadyForDeployment after COMPLETE",
    )
    assert env_after["State"] == "ReadyForDeployment", f"unexpected post-deploy env state: {env_after.get('State')!r}"

    # The data plane is AppConfigData (GetConfiguration is deprecated in its favour).
    acd = ctx.client("appconfigdata")
    token = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env["Id"],
        ConfigurationProfileIdentifier=profile_id,
    )["InitialConfigurationToken"]
    content = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
    assert content == payload, f"GetLatestConfiguration served {content!r}, expected {payload!r}"

    # Teardown in the check, bottom-up, then prove the application tree is gone and unusable.
    _purge_application(ac, app_id)
    ac.delete_deployment_strategy(DeploymentStrategyId=ds_id)

    code, status, message = _error(lambda: ac.get_deployment_strategy(DeploymentStrategyId=ds_id))
    assert code == "ResourceNotFoundException", f"GetDeploymentStrategy after delete: got {code!r}"
    assert status == 404, f"GetDeploymentStrategy after delete: expected HTTP 404, got {status!r}"
    expected_message = f"DeploymentStrategy with Id {ds_id} could not be found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed_ds = [d["Id"] for d in _purge_items(ac.get_paginator("list_deployment_strategies").paginate())]
    assert ds_id not in listed_ds, f"deleted deployment strategy {ds_id!r} is still listed by ListDeploymentStrategies"
    code, status, message = _error(
        lambda: ac.update_deployment_strategy(DeploymentStrategyId=ds_id, Description="post-delete probe")
    )
    assert code == "ResourceNotFoundException", f"UpdateDeploymentStrategy after delete: got {code!r}"
    assert status == 404, f"UpdateDeploymentStrategy after delete: expected HTTP 404, got {status!r}"
    expected_message = f"DeploymentStrategy with Id {ds_id} could not be found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    code, status, message = _error(lambda: ac.get_application(ApplicationId=app_id))
    assert code == "ResourceNotFoundException", f"GetApplication after delete: got {code!r}"
    assert status == 404, f"GetApplication after delete: expected HTTP 404, got {status!r}"
    expected_message = f"Application with Id {app_id} could not be found for account {ctx.account}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed = [a["Id"] for a in _purge_items(ac.get_paginator("list_applications").paginate())]
    assert app_id not in listed, f"deleted application {app_id!r} is still listed by ListApplications"
    code, status, message = _error(
        lambda: ac.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"))
    )
    assert code == "ResourceNotFoundException", f"CreateEnvironment under the deleted application: got {code!r}"
    assert status == 404, f"CreateEnvironment under the deleted application: expected HTTP 404, got {status!r}"
    expected_message = f"Application with Id {app_id} could not be found for account {ctx.account}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
