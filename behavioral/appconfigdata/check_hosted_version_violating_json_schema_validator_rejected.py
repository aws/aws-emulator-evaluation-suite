"""hosted-version-violating-json-schema-validator-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-version-violating-json-schema-validator-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfigdata"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A JSON_SCHEMA validator accepts an invalid hosted version at creation but StartDeployment of
    it raises BadRequestException and it is never served; a conforming version deploys and is
    served.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)

    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"enabled": {"type": "boolean"}},
        "required": ["enabled"],
        "additionalProperties": False,
    }
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-acd-validated-profile-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Validators=[{"Type": "JSON_SCHEMA", "Content": json.dumps(schema)}],
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
        )
    )

    # break exactly one thing: content that violates the schema (wrong type, missing required key)
    invalid_content = json.dumps({"enabled": "not-a-boolean"}).encode("utf-8")
    invalid_version = _create_hosted_version(ctx, app_id, profile_id, invalid_content, "application/json")

    # the invalid content is stored -- the validator does not run at creation time
    versions = appconfig.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )["Items"]
    stored_versions = [v["VersionNumber"] for v in versions]
    assert stored_versions == [invalid_version], (
        f"expected the invalid version {invalid_version} stored as-is, got {stored_versions}"
    )

    # the validator runs when a deployment of the invalid version is started
    code, message = _client_error(
        lambda: appconfig.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=_zero_bake_strategy(ctx, appconfig),
            ConfigurationProfileId=profile_id,
            ConfigurationVersion=str(invalid_version),
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected_message = (
        "Could not build JSON schema from invalid input:\n "
        + json.dumps(schema)
        + ".\n Original error message:\n"
        + '[message: "instance type (string) does not match any allowed primitive type '
        + '(allowed: [\\"boolean\\"])" - parent node: /enabled]'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: schema-conforming content is accepted, deployed, and served
    valid_content = json.dumps({"enabled": True}).encode("utf-8")
    version_number = _create_hosted_version(ctx, app_id, profile_id, valid_content, "application/json")
    _deploy_version(ctx, app_id, env_id, profile_id, version_number)

    appconfigdata = ctx.client("appconfigdata")
    token = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
    )["InitialConfigurationToken"]
    resp = appconfigdata.get_latest_configuration(ConfigurationToken=token)
    served = resp["Configuration"].read()
    assert served == valid_content, (
        f"expected the data plane to serve the valid content {valid_content!r}, got {served!r}"
    )


def _zero_bake_strategy(ctx, appconfig):
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-acd-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    )
    return strategy_id



def _client_error(fn):
    """Return (code, message) for a call that must be refused.

    Raises AssertionError when the call succeeds: an emulator that accepts what AWS refuses
    must fail loudly, not read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if code != "ResourceNotFoundException":
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-acd-app-"))["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(ApplicationId=app_id, Name=ctx.unique_name("sim2real-acd-env-"))["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    )
    return env_id


def _create_hosted_version(ctx, app_id, profile_id, content, content_type="application/json"):
    appconfig = ctx.client("appconfig")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
            )
        )
    )
    return version_number


def _deploy_version(ctx, app_id, env_id, profile_id, version_number, timeout_s=150.0):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-acd-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    )
    resp = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = resp["DeploymentNumber"]
    state = resp.get("State")
    deadline = time.monotonic() + timeout_s
    while state != "COMPLETE" and time.monotonic() < deadline:
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state {state}")
        time.sleep(3)
        state = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"]
    if state != "COMPLETE":
        raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s, last state={state}")
    return deployment_number


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
