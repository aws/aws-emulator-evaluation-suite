"""hosted-configuration-version-content-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-configuration-version-content-roundtrip"
GROUP = 'hosted-configuration-version'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-content-roundtrip"}

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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Hosted configuration version content and content-type are stored byte-exact."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]

    payload = b'{"enabled": true, "threshold": 42}'
    created = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=payload,
        ContentType="application/json",
    )
    version = created["VersionNumber"]

    got = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
    )
    body = got["Content"].read()
    assert body == payload, f"content mismatch: {body!r} != {payload!r}"
    assert got["ContentType"] == "application/json", (
        f"content-type mismatch: {got['ContentType']!r} != 'application/json'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
