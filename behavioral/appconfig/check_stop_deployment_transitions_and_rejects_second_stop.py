"""stop-deployment-transitions-and-rejects-second-stop."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-deployment-transitions-and-rejects-second-stop"
GROUP = 'deployment'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-stop-deployment-second-stop"}


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the second StopDeployment to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, timeout_s=45, interval_s=1.0, description="condition"):
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


def _drain_and_delete_app(ac, app_id):
    """Stop any in-flight deployments so the application can be deleted, then delete it.
    An environment in Deploying/RollingBack blocks deletion of its parent application."""
    try:
        envs = _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    for env in envs:
        if env.get("State") not in ("Deploying", "RollingBack"):
            continue
        env_id = env["Id"]
        try:
            deployments = _purge_items(
                ac.get_paginator("list_deployments").paginate(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                )
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            deployments = []
        for dep in deployments:
            if dep.get("State") in ("COMPLETE", "ROLLED_BACK", "REVERTED"):
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep["DeploymentNumber"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                e = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if e.get("State") not in ("Deploying", "RollingBack"):
                break
            time.sleep(2.0)
    # Children first, or DeleteApplication below is refused outright: AppConfig gates
    # DeleteApplication on child existence and DeleteConfigurationProfile on hosted-version
    # existence.
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
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopDeployment moves an in-flight deployment to a terminal state; stopping twice fails."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    env = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=15,
        GrowthFactor=10,
        FinalBakeTimeInMinutes=10,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"v1", ContentType="text/plain"
    )["VersionNumber"]

    started = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env["Id"],
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version),
    )
    deployment_number = started["DeploymentNumber"]

    stopped = ac.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=deployment_number
    )
    # StopDeployment acknowledges synchronously with a rollback/revert state; the
    # transition to a terminal state is asynchronous and polled for below.
    assert stopped["State"] in (
        "ROLLING_BACK",
        "ROLLED_BACK",
        "REVERTING",
        "REVERTED",
    ), f"unexpected post-stop state: {stopped.get('State')}"

    final = _poll_until(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=deployment_number
        ),
        lambda d: d.get("State") in ("ROLLED_BACK", "REVERTED"),
        timeout_s=30,
        interval_s=1.0,
        description="deployment reaching a stopped terminal state",
    )
    assert final["State"] in ("ROLLED_BACK", "REVERTED"), f"unexpected final state: {final['State']!r}"

    # A deployment already in a terminal state cannot be stopped again.
    err = _error(
        lambda: ac.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=deployment_number
        )
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err}"
    expected_message = (
        f"Deployment {deployment_number} for App {app_id} and Environment {env['Id']} cannot be stopped, "
        f"it has a status of {final['State']}."
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # The rejected second stop must have had no effect: an independent read (GetDeployment,
    # not StopDeployment) shows the deployment still in the same terminal state reached above.
    unchanged = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=deployment_number
    )
    assert unchanged["State"] == final["State"], (
        f"rejected second stop must not alter state: was {final['State']!r}, now {unchanged['State']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
