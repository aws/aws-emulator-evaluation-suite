"""schema-version-metadata-remove-unknown-pair-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-version-metadata-remove-unknown-pair-rejected"
GROUP = "schema-version"
SERVICES = ["glue"]

_AVRO_V1 = (
    '{"type":"record","name":"ShipmentEvent","namespace":"com.example.logistics",'
    '"fields":[{"name":"weightKg","type":"double"}]}'
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone.
    """

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected
    success raises instead.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveSchemaVersionMetadata for a key-value pair never stored is rejected, and
    the pair that was actually stored is unaffected by the refused call.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry)
    ctx.on_cleanup(
        _teardown(
            lambda: glue.delete_registry(RegistryId={"RegistryName": registry}),
            "EntityNotFoundException",
        )
    )

    schema_name = ctx.unique_name("sim2real-behav-remove-schema-")
    schema = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=_AVRO_V1,
    )
    version_id = schema["SchemaVersionId"]
    ctx.on_cleanup(
        _teardown(
            lambda: glue.delete_schema(
                SchemaId={"SchemaName": schema_name, "RegistryName": registry}
            ),
            "EntityNotFoundException",
        )
    )

    key = "dataset-tier"
    stored_value = "gold"
    unknown_value = "platinum"

    glue.put_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataKeyValue={"MetadataKey": key, "MetadataValue": stored_value},
    )

    code, message = _error(
        lambda: glue.remove_schema_version_metadata(
            SchemaVersionId=version_id,
            MetadataKeyValue={"MetadataKey": key, "MetadataValue": unknown_value},
        )
    )
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException removing an unstored pair, got {code}: {message!r}"
    )
    expected_message = f"Metadata is not found for the schema version. SchemaVersionId: {version_id} "
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    unaffected = glue.query_schema_version_metadata(SchemaVersionId=version_id)
    entry = unaffected["MetadataInfoMap"][key]
    assert entry["MetadataValue"] == stored_value, (
        f"the refused removal changed the stored value to {entry['MetadataValue']!r}"
    )
    assert entry["OtherMetadataValueList"] == [], (
        f"the refused removal left OtherMetadataValueList as {entry['OtherMetadataValueList']!r}"
    )

    glue.remove_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataKeyValue={"MetadataKey": key, "MetadataValue": stored_value},
    )
    after_removal = glue.query_schema_version_metadata(SchemaVersionId=version_id)
    assert after_removal["MetadataInfoMap"] == {}, (
        f"expected an empty MetadataInfoMap after removing the pair that was actually stored, "
        f"got {after_removal['MetadataInfoMap']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
