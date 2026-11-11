"""configuration-profile-invalid-location-uri-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-profile-invalid-location-uri-rejected"
GROUP = 'overly-permissive'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-configuration-profile-invalid-location-uri-rejected"}


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
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationProfile with an unsupported LocationUri scheme must fail validation,
    and the account must otherwise be healthy for the call (positive control), and the rejected
    attempt must leave no trace in the application's profile list (independent read)."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))

    # Positive control: a valid LocationUri is accepted, so a rejection below is provably about
    # the scheme, not a blanket denial of CreateConfigurationProfile in this account.
    valid_name = ctx.unique_name("sim2real-behav-cp-valid-")
    valid = ac.create_configuration_profile(
        ApplicationId=app_id, Name=valid_name, LocationUri="hosted", Tags=_TAGS,
    )
    assert valid["LocationUri"] == "hosted", valid

    rejected_name = ctx.unique_name("sim2real-behav-cp-rejected-")
    bad_uri = "ftp://not-a-supported-scheme/config"
    code, message = _error(
        lambda: ac.create_configuration_profile(
            ApplicationId=app_id,
            Name=rejected_name,
            LocationUri=bad_uri,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = (
        "1 validation error detected: Value null at 'retrievalRoleArn' failed to satisfy "
        f"constraint: Member must not be null if the request has the following uri: {bad_uri}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected attempt created nothing -- only the
    # positive control's profile exists for this application.
    surviving_names = {
        profile["Name"]
        for profile in _purge_items(
            ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
        )
    }
    assert surviving_names == {valid_name}, (
        f"expected only {valid_name!r} to exist, got {surviving_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
