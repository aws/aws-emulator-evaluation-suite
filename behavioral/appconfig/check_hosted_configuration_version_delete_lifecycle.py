"""hosted-configuration-version-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-configuration-version-delete-lifecycle"
GROUP = 'hosted-configuration-version'
SERVICES = ['appconfig']


# AppConfig teardown ORDER is load-bearing: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile is refused while any hosted
# configuration version survives. A bare DeleteApplication teardown raises BadRequestException, and
# because the runner swallows teardown exceptions the application tree would leak while the check
# passed. Bottom-up is the only order AppConfig accepts.

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

    Raises rather than leaking quietly: a purge that cannot finish is a real failure, even though
    the runner will swallow it.
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
        # Per environment, NOT one budget for the whole purge: a shared deadline that earlier
        # environments had already spent left the wait loop below never entering its body, so
        # `state` stayed None and the `else` raised "never left None during cleanup" for a
        # perfectly deletable environment -- aborting teardown before a single delete ran.
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
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


def _error(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleted hosted configuration version disappears from Get and List, and a second
    delete of the now-absent version is itself rejected rather than silently no-op'd."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-cp-"), LocationUri="hosted"
    )["Id"]
    created = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"data", ContentType="text/plain"
    )
    version = created["VersionNumber"]

    ac.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
    )

    code, code_msg = _error(
        lambda: ac.get_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get on a deleted version, got {code!r}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Hosted Configuration Version with Application Id {app_id}, Configuration Profile Id "
        f"{profile_id}, and Version {version} could not be found for account {account}"
    ), f"unexpected message: {code_msg!r}"

    listed = ac.list_hosted_configuration_versions(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    listed_numbers = [item["VersionNumber"] for item in listed["Items"]]
    assert version not in listed_numbers, (
        f"deleted version {version} still present in ListHostedConfigurationVersions: {listed_numbers}"
    )

    # a mutation on the now-dead id must also fail, not silently no-op
    second_delete_code, second_delete_code_msg = _error(
        lambda: ac.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    )
    assert second_delete_code == "ResourceNotFoundException", (
        "expected a second delete of an already-deleted version to fail with "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    assert second_delete_code_msg == (
        f"Hosted Configuration Version with Application Id {app_id}, Configuration Profile Id "
        f"{profile_id}, and Version {version} could not be found for account {account}"
    ), f"unexpected message: {second_delete_code_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
