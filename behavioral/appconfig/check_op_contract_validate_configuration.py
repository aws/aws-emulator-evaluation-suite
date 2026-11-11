"""op-contract-validateConfiguration."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-validateConfiguration"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateConfiguration succeeds (HTTP 204, empty body) for a hosted
    configuration version that satisfies the profile's JSON Schema validator,
    and rejects a version that violates the schema with BadRequestException."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"flag": {"type": "boolean"}},
        "required": ["flag"],
        "additionalProperties": False,
    }
    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Validators=[{"Type": "JSON_SCHEMA", "Content": json.dumps(schema)}],
    )["Id"]
    # DeleteApplication is refused (BadRequestException) while the configuration profile
    # survives. Cleanups run LIFO, so registering child-then-parent here tears down bottom-up
    # without a separate purge.
    ctx.on_cleanup(lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id))

    valid_version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=json.dumps({"flag": True}).encode(),
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=valid_version
        )
    )
    invalid_version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=json.dumps({"flag": "not-a-boolean"}).encode(),
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=invalid_version
        )
    )

    ok = appconfig.validate_configuration(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, ConfigurationVersion=str(valid_version)
    )
    # The Smithy model pins the success response at exactly HTTP 204 (`smithy.api#http.code`),
    # not "any 2xx".
    status = ok["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 204, f"expected the modelled HTTP 204 success response, got HTTP {status}"

    err = _error(
        lambda: appconfig.validate_configuration(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(invalid_version),
        )
    )
    assert err["Code"] == "BadRequestException", f"schema-violating content must be rejected, got {err}"
    expected_message = (
        f"Could not build JSON schema from invalid input:\n {json.dumps(schema)}.\n Original error message:\n"
        r'[message: "instance type (string) does not match any allowed primitive type (allowed: [\"boolean\"])"'
        " - parent node: /flag]"
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected ValidateConfiguration to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
