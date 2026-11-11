"""validate-configuration-schema."""
from __future__ import annotations

import time

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-configuration-schema"
GROUP = 'validate-configuration'
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
_TAGS = {"sim2real:managed": "true", "sim2real": "validate-configuration-schema"}


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
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateConfiguration accepts content matching a JSON Schema validator, rejects violations."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"enabled": {"type": "boolean"}},
        "required": ["enabled"],
    }

    profile = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Validators=[{"Type": "JSON_SCHEMA", "Content": json.dumps(schema)}],
        Tags=_TAGS,
    )
    profile_id = profile["Id"]

    valid_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps({"enabled": True}).encode(),
        ContentType="application/json",
    )["VersionNumber"]
    # Positive control: schema-conforming content must validate cleanly.
    ok = ac.validate_configuration(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, ConfigurationVersion=str(valid_version)
    )
    ok_status = ok["ResponseMetadata"]["HTTPStatusCode"]
    assert ok_status in (200, 204), f"expected a successful validation response, got HTTP {ok_status}"

    invalid_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps({"enabled": "not-a-boolean"}).encode(),
        ContentType="application/json",
    )["VersionNumber"]
    code, message = _error(
        lambda: ac.validate_configuration(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, ConfigurationVersion=str(invalid_version)
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    # AWS renders the validator content (json.dumps of the schema) back into the message.
    expected = (
        f"Could not build JSON schema from invalid input:\n {json.dumps(schema)}.\n"
        ' Original error message:\n[message: "instance type (string) does not match any allowed'
        ' primitive type (allowed: [\\"boolean\\"])" - parent node: /enabled]'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
