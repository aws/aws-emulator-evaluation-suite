"""get-schema-version-by-never-registered-version-number-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-schema-version-by-never-registered-version-number-rejected"
GROUP = "schema-rejected"
SERVICES = ["glue"]

_AVRO_DEFINITION = (
    '{"type":"record","name":"Shipment","namespace":"com.example.shipment",'
    '"fields":[{"name":"shipmentId","type":"string"}]}'
)


def _expect_error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """get_schema_version by SchemaId and a VersionNumber no RegisterSchemaVersion call ever
    minted raises EntityNotFoundException; VersionNumber 1, which was minted, still resolves.
    """
    glue = ctx.client("glue")
    registry_name = ctx.unique_name("sim2real-glue-reg")
    glue.create_registry(RegistryName=registry_name)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name}))

    schema_name = ctx.unique_name("sim2real-glue-schema")
    glue.create_schema(
        RegistryId={"RegistryName": registry_name},
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="NONE",
        SchemaDefinition=_AVRO_DEFINITION,
    )
    ctx.on_cleanup(
        lambda: glue.delete_schema(
            SchemaId={"RegistryName": registry_name, "SchemaName": schema_name}
        )
    )

    schema_id = {"RegistryName": registry_name, "SchemaName": schema_name}
    code, message = _expect_error(
        lambda: glue.get_schema_version(
            SchemaId=schema_id, SchemaVersionNumber={"VersionNumber": 5}
        )
    )
    assert code == "EntityNotFoundException", (
        f"get_schema_version on VersionNumber 5, never registered, raised {code}: {message!r}, "
        "expected EntityNotFoundException"
    )
    assert message == (
        f"Schema version is not found. RegistryName: {registry_name}, SchemaName: {schema_name}, "
        "SchemaArn: null, VersionNumber: 5, isLatestVersion: false"
    ), f"unexpected message {message!r}"

    # Positive control: the minted version 1 still resolves through the same lookup shape.
    control = glue.get_schema_version(
        SchemaId=schema_id, SchemaVersionNumber={"VersionNumber": 1}
    )
    assert control["VersionNumber"] == 1, (
        f"control read returned VersionNumber={control.get('VersionNumber')!r}, expected 1"
    )
    assert control["SchemaDefinition"] == _AVRO_DEFINITION, (
        f"control read returned SchemaDefinition={control['SchemaDefinition']!r}, "
        f"expected the definition unchanged from create_schema: {_AVRO_DEFINITION!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
