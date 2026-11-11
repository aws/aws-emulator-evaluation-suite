"""schema-mapping-create-get-delete-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-mapping-create-get-delete-roundtrip"
GROUP = "control-plane"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchemaMapping persists mappedInputFields/matchKeys and GetSchemaMapping reflects
    hasWorkflows=False until a workflow references it; DeleteSchemaMapping removes it."""
    er = ctx.client("entityresolution")
    name = ctx.unique_name("sim2real-er-schema-")
    fields = [
        {"fieldName": "id", "type": "UNIQUE_ID"},
        {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        {"fieldName": "name", "type": "NAME", "matchKey": "name"},
    ]
    er.create_schema_mapping(
        schemaName=name,
        description="sim2real behavioral check",
        mappedInputFields=fields,
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, name))

    got = er.get_schema_mapping(schemaName=name)
    assert got["schemaName"] == name, f"expected schemaName={name!r}, got {got['schemaName']!r}"
    assert got["hasWorkflows"] is False, f"expected hasWorkflows=False, got {got['hasWorkflows']!r}"
    field_by_name = {f["fieldName"]: f for f in got["mappedInputFields"]}
    assert set(field_by_name) == {"id", "email", "name"}, (
        f"expected fields {{'id', 'email', 'name'}}, got {set(field_by_name)!r}"
    )
    assert field_by_name["email"]["matchKey"] == "email", (
        f"expected email matchKey='email', got {field_by_name['email'].get('matchKey')!r}"
    )
    assert field_by_name["name"]["matchKey"] == "name", (
        f"expected name matchKey='name', got {field_by_name['name'].get('matchKey')!r}"
    )

    er.delete_schema_mapping(schemaName=name)
    code, code_message = _error(lambda: er.get_schema_mapping(schemaName=name))
    assert code == "ResourceNotFoundException", (
        f"expected GetSchemaMapping on deleted schema to raise ResourceNotFoundException, got {code!r}"
    )
    expected = "SchemaMapping does not exist"
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"

    update_code, update_code_message = _error(
        lambda: er.update_schema_mapping(schemaName=name, mappedInputFields=fields)
    )
    assert update_code == "ResourceNotFoundException", (
        "expected UpdateSchemaMapping on deleted schema to raise ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    expected = "SchemaMapping does not exist"
    assert update_code_message == expected, f"expected message {expected!r}, got {update_code_message!r}"

    er.create_schema_mapping(
        schemaName=name,
        description="sim2real behavioral check (recreated after delete)",
        mappedInputFields=fields,
        tags={"sim2real-check": CHECK},
    )
    recreated = er.get_schema_mapping(schemaName=name)
    assert recreated["schemaName"] == name, (
        f"expected the deleted schemaName={name!r} to be reusable, got {recreated['schemaName']!r}"
    )


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
