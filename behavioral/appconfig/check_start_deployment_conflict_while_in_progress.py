"""start-deployment-conflict-while-in-progress."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-deployment-conflict-while-in-progress"
GROUP = 'deployment'
SERVICES = ['appconfig']


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, so a call
    accepted where AWS refuses it fails as a success, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second StartDeployment on the same environment while one is in-flight must conflict,
    the rejected attempt must leave no second deployment record, and the identical call must
    succeed once the in-flight deployment is stopped."""
    ac = ctx.client("appconfig")
    # Long duration so the first deployment stays in-progress for the assertion window.
    slow_ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=15,
        GrowthFactor=10,
        FinalBakeTimeInMinutes=10,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=slow_ds_id))
    other_ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=other_ds_id))
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    # Drain + delete the app FIRST at teardown (registered after the strategies => runs
    # before them under LIFO).
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))
    env = ac.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"))
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-cp-"), LocationUri="hosted"
    )["Id"]
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"v1", ContentType="text/plain"
    )["VersionNumber"]

    first = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env["Id"],
        DeploymentStrategyId=slow_ds_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version),
    )
    first_dep_num = first["DeploymentNumber"]

    # Environment transitions into 'Deploying' (CamelCase) after StartDeployment.
    env_during = _poll_until(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=env["Id"]),
        lambda e: e.get("State") == "Deploying",
        timeout_s=45,
        interval_s=1.0,
        description="environment entering Deploying",
    )
    assert env_during["State"] == "Deploying", f"expected Deploying, got {env_during.get('State')!r}"

    def _attempt_second():
        return ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env["Id"],
            DeploymentStrategyId=other_ds_id,
            ConfigurationProfileId=profile_id,
            ConfigurationVersion=str(version),
        )

    err = _error(_attempt_second)
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']}"
    assert err["Message"] == (
        f"Environment {env['Id']} currently has a state of DEPLOYING. The current deployment "
        "must finish before a new deployment can be started."
    ), f"unexpected message: {err['Message']!r}"

    # Effect-absent: the rejected attempt must not have created a second deployment record.
    # An independent read (ListDeployments, not StartDeployment's own response) is the proof.
    listed = ac.list_deployments(ApplicationId=app_id, EnvironmentId=env["Id"]).get("Items", [])
    listed_numbers = sorted(d["DeploymentNumber"] for d in listed)
    assert listed_numbers == [first_dep_num], (
        f"expected only deployment {first_dep_num} to exist after the rejected attempt, "
        f"ListDeployments shows {listed_numbers}"
    )

    # Restore: stop the blocking deployment and wait for it to leave Deploying, then prove
    # the identical second call is accepted once the state that forbade it is gone.
    stopped = ac.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=first_dep_num
    )
    assert stopped["State"] in ("ROLLING_BACK", "ROLLED_BACK", "REVERTING", "REVERTED"), (
        f"unexpected post-stop state: {stopped.get('State')!r}"
    )
    _poll_until(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=env["Id"]),
        lambda e: e.get("State") not in ("Deploying", "RollingBack"),
        timeout_s=45,
        interval_s=1.0,
        description="environment leaving Deploying after stop",
    )

    second = _attempt_second()
    second_dep_num = second["DeploymentNumber"]
    assert second_dep_num > first_dep_num, (
        f"expected the restored StartDeployment to be accepted with a new deployment number "
        f"greater than {first_dep_num}, got {second_dep_num}"
    )

    # Terminal assertion is an independent read (GetDeployment), not StartDeployment's own
    # response: the restored deployment must actually exist at the destination.
    confirmed = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=second_dep_num
    )
    assert confirmed["DeploymentNumber"] == second_dep_num, (
        f"expected an independent GetDeployment read to show the restored deployment "
        f"{second_dep_num}, got {confirmed.get('DeploymentNumber')!r}"
    )

    def _stop_second():
        ids = {"ApplicationId": app_id, "EnvironmentId": env["Id"], "DeploymentNumber": second_dep_num}
        try:
            if ac.get_deployment(**ids)["State"] not in ("COMPLETE", "ROLLED_BACK", "REVERTED"):
                ac.stop_deployment(**ids)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_stop_second)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
