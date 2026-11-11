"""get-schema-mapping-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-schema-mapping-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["entityresolution"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSchemaMapping for a never-created schemaName fails with ResourceNotFoundException and its exact
    message, while a schema mapping created in the same run is readable."""
    er = ctx.client("entityresolution")
    real_name = ctx.unique_name("sim2real-er-real-")
    missing_name = ctx.unique_name("sim2real-er-missing-")

    er.create_schema_mapping(
        schemaName=real_name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, real_name))

    # Positive control: the real schema mapping is readable before we trust a
    # ResourceNotFoundException on a different name to mean "not found" rather
    # than "every GetSchemaMapping call is rejected".
    control = er.get_schema_mapping(schemaName=real_name)
    assert control["schemaName"] == real_name, (
        f"expected positive control to read {real_name}, got {control.get('schemaName')}"
    )

    code, code_message = _error(lambda: er.get_schema_mapping(schemaName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "SchemaMapping does not exist"
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"


def _error(fn, description="the call"):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected {description} to raise a ClientError, but it SUCCEEDED and returned {result!r}")


def _safe_delete_schema(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
