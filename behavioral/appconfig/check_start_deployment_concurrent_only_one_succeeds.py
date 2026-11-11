"""start-deployment-concurrent-only-one-succeeds."""
from __future__ import annotations

import concurrent.futures
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-deployment-concurrent-only-one-succeeds"
GROUP = 'overly-permissive'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-start-deployment-race"}


def _exc_error_code(exc) -> str:
    return (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code") or type(exc).__name__


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent StartDeployment calls against the same idle Environment must resolve
    to exactly one success; the loser gets ConflictException (no double-deploy race)."""
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
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"v1", ContentType="text/plain"
    )["VersionNumber"]
    # Long duration so the winning deployment stays in-progress, forcing the loser to conflict.
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=1440,
        GrowthFactor=1,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    # Drain + delete the app FIRST at teardown (registered last => runs first under LIFO),
    # before the deployment strategy is deleted.
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))

    def racer():
        return ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env["Id"],
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=profile_id,
            ConfigurationVersion=str(version),
        )["DeploymentNumber"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(racer) for _ in range(2)]
        results = []
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001 — captured for assertion
                results.append(exc)

    successes = [r for r in results if not isinstance(r, BaseException)]
    error_codes = [_exc_error_code(r) for r in results if isinstance(r, BaseException)]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)} (codes={error_codes})"
    assert error_codes.count("ConflictException") == 1, (
        f"expected exactly 1 ConflictException among the losers, got codes={error_codes}"
    )

    # Independent terminal read at the destination: a different operation than the one that
    # raced (StartDeployment) must agree that exactly one deployment exists and it is the winner.
    winner_number = successes[0]
    dep = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=winner_number
    )
    assert dep["DeploymentNumber"] == winner_number, (
        f"expected GetDeployment to echo DeploymentNumber {winner_number}, got {dep['DeploymentNumber']}"
    )
    assert dep["State"] not in ("ROLLED_BACK", "REVERTED"), (
        f"winning deployment {winner_number} already reached failure state {dep['State']!r}"
    )

    all_deployments = _purge_items(
        ac.get_paginator("list_deployments").paginate(ApplicationId=app_id, EnvironmentId=env["Id"])
    )
    assert len(all_deployments) == 1, (
        f"expected exactly 1 deployment recorded at the destination (proving the loser never "
        f"created one), got {len(all_deployments)}: {[d.get('DeploymentNumber') for d in all_deployments]}"
    )
    assert all_deployments[0]["DeploymentNumber"] == winner_number, (
        f"the sole recorded deployment {all_deployments[0].get('DeploymentNumber')} is not the "
        f"winner {winner_number}"
    )

    # Cleanup: stop whichever deployment won so teardown can proceed.
    try:
        ac.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeploymentNumber=winner_number
        )
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
