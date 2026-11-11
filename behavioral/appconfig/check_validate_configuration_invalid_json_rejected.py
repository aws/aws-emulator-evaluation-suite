"""validate-configuration-invalid-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-configuration-invalid-json-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-validate-configuration-invalid-json"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateConfiguration rejects malformed JSON content and, distinctly, JSON that is
    syntactically valid but violates the profile's JSON Schema -- both as BadRequestException
    with different failure details -- while a schema-conforming version validates cleanly."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "object",
        "properties": {"enabled": {"type": "boolean"}},
        "required": ["enabled"],
        "additionalProperties": False,
    }
    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name="cp-validate",
        LocationUri="hosted",
        Type="AWS.Freeform",
        Validators=[{"Type": "JSON_SCHEMA", "Content": json.dumps(schema)}],
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    v_malformed = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"enabled": true',  # missing closing brace: not valid JSON at all
        ContentType="application/json",
    )["VersionNumber"]
    v_schema_mismatch = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"enabled": "not-a-boolean"}',  # valid JSON, violates the schema's type constraint
        ContentType="application/json",
    )["VersionNumber"]
    v_valid = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"enabled": true}',
        ContentType="application/json",
    )["VersionNumber"]
    for v in (v_malformed, v_schema_mismatch, v_valid):
        ctx.on_cleanup(lambda v=v: _safe_delete_version(appconfig, app_id, cp_id, v))

    code_malformed, message_malformed = _error(
        lambda: appconfig.validate_configuration(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, ConfigurationVersion=str(v_malformed)
        )
    )
    assert code_malformed == "BadRequestException", f"malformed JSON: expected BadRequestException, got {code_malformed}"
    # AWS renders the validator content (json.dumps of the schema) back into the message, and
    # reads the unparseable document as a JSON string, so it fails the root "object" type.
    expected_malformed = (
        f"Could not build JSON schema from invalid input:\n {json.dumps(schema)}.\n"
        ' Original error message:\n[message: "instance type (string) does not match any allowed'
        ' primitive type (allowed: [\\"object\\"])" - parent node: /]'
    )
    assert message_malformed == expected_malformed, (
        f"malformed JSON: expected message {expected_malformed!r}, got {message_malformed!r}"
    )

    code_mismatch, message_mismatch = _error(
        lambda: appconfig.validate_configuration(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, ConfigurationVersion=str(v_schema_mismatch)
        )
    )
    assert code_mismatch == "BadRequestException", f"schema mismatch: expected BadRequestException, got {code_mismatch}"
    expected_mismatch = (
        f"Could not build JSON schema from invalid input:\n {json.dumps(schema)}.\n"
        ' Original error message:\n[message: "instance type (string) does not match any allowed'
        ' primitive type (allowed: [\\"boolean\\"])" - parent node: /enabled]'
    )
    assert message_mismatch == expected_mismatch, (
        f"schema mismatch: expected message {expected_mismatch!r}, got {message_mismatch!r}"
    )

    # Both are BadRequestException, but distinct failure paths (parse error vs. schema violation)
    # produce distinguishable failure details.
    assert message_malformed and message_mismatch and message_malformed != message_mismatch, (
        "expected distinct failure messages for malformed-JSON vs schema-mismatch validation errors"
    )

    # Positive control: a schema-conforming version validates without error (204/empty response).
    resp_ok = appconfig.validate_configuration(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, ConfigurationVersion=str(v_valid)
    )
    status_ok = resp_ok["ResponseMetadata"]["HTTPStatusCode"]
    assert status_ok == 204, f"schema-conforming version: expected HTTP 204, got {status_ok}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_profile(appconfig, app_id, cp_id):
    try:
        appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_version(appconfig, app_id, cp_id, version_number):
    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version_number
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
