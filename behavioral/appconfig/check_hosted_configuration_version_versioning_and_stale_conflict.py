"""hosted-configuration-version-versioning-and-stale-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-configuration-version-versioning-and-stale-conflict"
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
    """Call fn() and return its botocore Error dict; an unexpected success raises, so a target
    that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VersionNumber increments monotonically; a stale LatestVersionNumber is rejected."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-cp-"), LocationUri="hosted"
    )["Id"]

    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"v1", ContentType="text/plain"
    )
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"v2", ContentType="text/plain"
    )
    assert v2["VersionNumber"] == v1["VersionNumber"] + 1, (
        f"expected v2 to be v1+1, got v1={v1['VersionNumber']} v2={v2['VersionNumber']}"
    )

    listed = ac.list_hosted_configuration_versions(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    numbers = sorted(item["VersionNumber"] for item in listed["Items"])
    assert v1["VersionNumber"] in numbers and v2["VersionNumber"] in numbers, (
        f"expected {v1['VersionNumber']} and {v2['VersionNumber']} in listed versions, got {numbers}"
    )

    # Supplying a stale LatestVersionNumber (v1, when v2 is now latest) must be a
    # conflict - this is the optimistic-concurrency guard on hosted versions.
    err = _error(
        lambda: ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            Content=b"v3-stale",
            ContentType="text/plain",
            LatestVersionNumber=v1["VersionNumber"],
        )
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']}"
    assert err["Message"] == (
        f"Expected latest version {v1['VersionNumber']} does not match actual latest version "
        f"{v2['VersionNumber']}"
    ), f"unexpected message: {err['Message']!r}"

    # Effect-absent: the rejected stale write must not have landed anywhere.
    after_stale = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )
    after_stale_numbers = sorted(item["VersionNumber"] for item in after_stale["Items"])
    assert after_stale_numbers == numbers, (
        f"stale write must leave no trace: expected {numbers}, got {after_stale_numbers}"
    )

    # Restore: the identical call, now supplying the CURRENT LatestVersionNumber (v2),
    # must succeed. Without this leg, a target that rejects every LatestVersionNumber-
    # bearing create (not just stale ones) would pass the assertions above identically.
    v3 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=b"v3-current",
        ContentType="text/plain",
        LatestVersionNumber=v2["VersionNumber"],
    )
    assert v3["VersionNumber"] == v2["VersionNumber"] + 1, (
        f"expected a create with the correct current LatestVersionNumber to succeed as "
        f"v2+1, got v2={v2['VersionNumber']} v3={v3['VersionNumber']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
