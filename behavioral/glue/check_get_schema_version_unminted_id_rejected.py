"""get-schema-version-unminted-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-schema-version-unminted-id-rejected"
GROUP = "schema"
SERVICES = ["glue"]

_SCHEMA_DEFINITION = (
    '{"type":"record","name":"Catalog","namespace":"com.example.catalog",'
    '"fields":[{"name":"id","type":"long"}]}'
)


def _expect_error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected an error, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """get_schema_version on a well-formed SchemaVersionId that was never minted raises
    EntityNotFoundException; the real minted id still resolves to its own schema.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    schema_name = ctx.unique_name("sim2real-behav-avro-")
    created = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="NONE",
        SchemaDefinition=_SCHEMA_DEFINITION,
    )
    real_version_id = created["SchemaVersionId"]

    unminted_version_id = str(uuid.uuid4())
    while unminted_version_id == real_version_id:
        unminted_version_id = str(uuid.uuid4())

    code, message = _expect_error(
        lambda: glue.get_schema_version(SchemaVersionId=unminted_version_id)
    )
    assert code == "EntityNotFoundException", (
        f"expected get_schema_version on an unminted id to raise EntityNotFoundException, "
        f"got {code}"
    )
    assert message == "Schema is not found", f"expected message 'Schema is not found', got {message!r}"

    # Positive control: the real minted id still resolves, to its own schema definition.
    control = glue.get_schema_version(SchemaVersionId=real_version_id)
    assert control["SchemaVersionId"] == real_version_id, (
        f"expected the control read to return SchemaVersionId={real_version_id!r}, "
        f"got {control.get('SchemaVersionId')!r}"
    )
    assert control["SchemaDefinition"] == _SCHEMA_DEFINITION, (
        f"expected the control read to return the schema definition verbatim, "
        f"got {control.get('SchemaDefinition')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
