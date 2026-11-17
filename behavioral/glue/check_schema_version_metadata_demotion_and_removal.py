"""schema-version-metadata-demotion-and-removal."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-version-metadata-demotion-and-removal"
GROUP = "schema-version"
SERVICES = ["glue"]

_AVRO_V1 = (
    '{"type":"record","name":"PaymentEvent","namespace":"com.example.payments",'
    '"fields":[{"name":"amount","type":"double"}]}'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second metadata value for a key demotes the first into OtherMetadataValueList,
    holding exactly it; removing both values of the only key empties MetadataInfoMap.
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

    schema_name = ctx.unique_name("sim2real-behav-demote-schema-")
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

    key = "owner-team"
    first_value = "payments-team"
    second_value = "fraud-detection-team"

    first_put = glue.put_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataKeyValue={"MetadataKey": key, "MetadataValue": first_value},
    )
    assert first_put["MetadataKey"] == key, first_put["MetadataKey"]
    assert first_put["MetadataValue"] == first_value, first_put["MetadataValue"]

    second_put = glue.put_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataKeyValue={"MetadataKey": key, "MetadataValue": second_value},
    )
    assert second_put["MetadataKey"] == key, second_put["MetadataKey"]
    assert second_put["MetadataValue"] == second_value, second_put["MetadataValue"]

    after_second_put = glue.query_schema_version_metadata(SchemaVersionId=version_id)
    entry = after_second_put["MetadataInfoMap"][key]
    assert entry["MetadataValue"] == second_value, (
        f"expected the current value to be {second_value!r}, got {entry['MetadataValue']!r}"
    )
    others = [item["MetadataValue"] for item in entry["OtherMetadataValueList"]]
    assert others == [first_value], (
        f"expected the demoted value to be exactly [{first_value!r}], got {others!r}"
    )

    # The demoted value is still a real, independently retrievable pair, not merely an
    # echo of the earlier PutSchemaVersionMetadata response: a search scoped to it finds it.
    filtered = glue.query_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataList=[{"MetadataKey": key, "MetadataValue": first_value}],
    )
    filtered_entry = filtered["MetadataInfoMap"][key]
    assert filtered_entry["MetadataValue"] == first_value, (
        f"a metadata search scoped to {key!r}={first_value!r} returned "
        f"{filtered_entry['MetadataValue']!r} instead"
    )

    glue.remove_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataKeyValue={"MetadataKey": key, "MetadataValue": first_value},
    )
    after_remove_demoted = glue.query_schema_version_metadata(SchemaVersionId=version_id)
    entry = after_remove_demoted["MetadataInfoMap"][key]
    assert entry["MetadataValue"] == second_value, (
        f"removing the demoted value changed the current value to {entry['MetadataValue']!r}"
    )
    assert entry["OtherMetadataValueList"] == [], (
        f"expected an empty OtherMetadataValueList after removing the only demoted value, "
        f"got {entry['OtherMetadataValueList']!r}"
    )

    glue.remove_schema_version_metadata(
        SchemaVersionId=version_id,
        MetadataKeyValue={"MetadataKey": key, "MetadataValue": second_value},
    )
    after_remove_last = glue.query_schema_version_metadata(SchemaVersionId=version_id)
    assert after_remove_last["MetadataInfoMap"] == {}, (
        f"expected an empty MetadataInfoMap after removing the only key's last value, "
        f"got {after_remove_last['MetadataInfoMap']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
