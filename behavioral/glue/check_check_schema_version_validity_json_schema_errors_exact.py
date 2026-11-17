"""check-schema-version-validity-json-schema-errors-exact."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "check-schema-version-validity-json-schema-errors-exact"
GROUP = "schema"
SERVICES = ["glue"]

_VALID_SCHEMA = (
    '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object",'
    '"properties":{"id":{"type":"integer"}},"required":["id"],'
    '"additionalProperties":false}'
)

_TRUNCATED_SCHEMA = '{"type": "object",'

_UNKNOWN_TYPE_SCHEMA = (
    '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object",'
    '"properties":{"id":{"type":"notarealtype"}}}'
)

_TRUNCATED_RESULT = (
    False,
    "Unexpected end-of-input within/between Object entries\n"
    " at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); "
    "line: 1, column: 19]",
)

_UNKNOWN_TYPE_RESULT = (
    False,
    "[$.properties.id.type: does not have a value in the enumeration "
    "[array, boolean, integer, null, number, object, string], $.properties.id.type: "
    "should be valid to any of the schemas array]",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckSchemaVersionValidity on JSON pins the exact Error text for a truncated definition and
    for an unknown JSON Schema `type` keyword value, beside a valid-schema control."""
    glue = ctx.client("glue")

    control = glue.check_schema_version_validity(DataFormat="JSON", SchemaDefinition=_VALID_SCHEMA)
    assert control["Valid"] is True, f"a well-formed draft-07 object schema must be valid: {control}"
    assert not control.get("Error"), f"a valid schema must carry no Error: {control}"

    truncated = glue.check_schema_version_validity(
        DataFormat="JSON", SchemaDefinition=_TRUNCATED_SCHEMA
    )
    _assert_result(truncated, _TRUNCATED_RESULT, "a truncated JSON definition")

    unknown_type = glue.check_schema_version_validity(
        DataFormat="JSON", SchemaDefinition=_UNKNOWN_TYPE_SCHEMA
    )
    _assert_result(unknown_type, _UNKNOWN_TYPE_RESULT, "a schema with an unknown `type` keyword value")


def _assert_result(resp, expected, label):
    valid, error = expected
    assert resp["Valid"] is valid, f"{label} must report Valid={valid}: {resp}"
    assert resp.get("Error") == error, f"{label} must report Error={error!r}, got {resp.get('Error')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
