"""check-schema-version-validity-rejects-malformed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "check-schema-version-validity-rejects-malformed"
GROUP = 'overly-permissive'
SERVICES = ['glue']

AVRO_VALID = (
    '{"type":"record","name":"Order","namespace":"com.example",'
    '"fields":[{"name":"id","type":"long"}]}'
)


@tags("axis:rejection", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CheckSchemaVersionValidity must report Valid=False for a malformed AVRO definition.

    A well-formed AVRO record is the positive control: without it, "rejects malformed AVRO"
    is indistinguishable from an endpoint that reports every definition invalid.
    """
    glue = ctx.client("glue")
    control = glue.check_schema_version_validity(DataFormat="AVRO", SchemaDefinition=AVRO_VALID)
    assert control["Valid"] is True, (
        f"a well-formed AVRO record must be reported valid: {control}"
    )

    resp = glue.check_schema_version_validity(
        DataFormat="AVRO",
        SchemaDefinition='{"type":"record","name":"Broken","fields":"not-a-list"}',
    )
    assert resp["Valid"] is False, (
        f"a malformed AVRO definition must not be reported as valid: {resp}"
    )
    assert resp.get("Error"), f"an invalid definition must come with an Error message: {resp}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
