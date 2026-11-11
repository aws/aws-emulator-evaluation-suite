"""create-schema-mapping-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schema-mapping-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["entityresolution"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchemaMapping with a schemaName that already exists raises ConflictException and
    leaves the original schema mapping's fields untouched; creating under a fresh, unused name
    in the same file still succeeds."""
    er = ctx.client("entityresolution")
    name = ctx.unique_name("sim2real-er-dupname-")
    original_fields = [
        {"fieldName": "id", "type": "UNIQUE_ID"},
        {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
    ]
    er.create_schema_mapping(
        schemaName=name, mappedInputFields=original_fields, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: _safe_delete(er, name))

    code, code_message = _error(
        lambda: er.create_schema_mapping(
            schemaName=name,
            mappedInputFields=[
                {"fieldName": "id", "type": "UNIQUE_ID"},
                {"fieldName": "phone", "type": "PHONE_NUMBER", "matchKey": "phone"},
            ],
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = "SchemaMapping already exists."
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"

    got = er.get_schema_mapping(schemaName=name)
    field_names = {f["fieldName"] for f in got["mappedInputFields"]}
    assert field_names == {"id", "email"}, "the conflicting create must not have mutated the schema"

    other_name = ctx.unique_name("sim2real-er-freshname-")
    er.create_schema_mapping(
        schemaName=other_name, mappedInputFields=original_fields, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: _safe_delete(er, other_name))
    got_other = er.get_schema_mapping(schemaName=other_name)["schemaName"]
    assert got_other == other_name, f"expected schemaName {other_name!r}, got {got_other!r}"


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
