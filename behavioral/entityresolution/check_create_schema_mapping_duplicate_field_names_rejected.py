"""create-schema-mapping-duplicate-field-names-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schema-mapping-duplicate-field-names-rejected"
GROUP = "overly-permissive"
SERVICES = ["entityresolution"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchemaMapping rejects mappedInputFields containing two entries with the same
    fieldName with ValidationException; the schema mapping is never created (absent from
    GetSchemaMapping), while a well-formed sibling request in the same file succeeds."""
    er = ctx.client("entityresolution")
    bad_name = ctx.unique_name("sim2real-er-dupfields-")

    code, code_message = _error(
        lambda: er.create_schema_mapping(
            schemaName=bad_name,
            mappedInputFields=[
                {"fieldName": "id", "type": "UNIQUE_ID"},
                {"fieldName": "id", "type": "EMAIL_ADDRESS"},
            ],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "SchemaMapping is not allowed to have repeated input fields in attributes: id"
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"
    absent_code, absent_code_message = _error(lambda: er.get_schema_mapping(schemaName=bad_name))
    assert absent_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created mapping, got {absent_code!r}"
    )
    expected = "SchemaMapping does not exist"
    assert absent_code_message == expected, f"expected message {expected!r}, got {absent_code_message!r}"

    good_name = ctx.unique_name("sim2real-er-goodfields-")
    er.create_schema_mapping(
        schemaName=good_name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
        tags={"sim2real": "behavioral"},
    )
    ctx.on_cleanup(lambda: _safe_delete(er, good_name))
    got_name = er.get_schema_mapping(schemaName=good_name)["schemaName"]
    assert got_name == good_name, f"expected the well-formed sibling {good_name!r} to exist, got {got_name!r}"


def _error(fn, description="the call"):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected {description} to raise a ClientError, but it SUCCEEDED and returned {result!r}")


def _safe_delete(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
