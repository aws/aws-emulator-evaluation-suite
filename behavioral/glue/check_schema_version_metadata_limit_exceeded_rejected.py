"""schema-version-metadata-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-version-metadata-limit-exceeded-rejected"
GROUP = "schema-version"
SERVICES = ["glue"]

_AVRO_V1 = (
    '{"type":"record","name":"Order","namespace":"com.example",'
    '"fields":[{"name":"id","type":"long"}]}'
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A schema version holds at most 10 metadata key value pairs; the 11th is rejected
    and the 10 accepted ones remain exactly as queried.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    schema_name = ctx.unique_name("sim2real-behav-limit-schema-")
    schema = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=_AVRO_V1,
    )
    version_id = schema["SchemaVersionId"]
    ctx.on_cleanup(
        lambda: glue.delete_schema(SchemaId={"SchemaName": schema_name, "RegistryName": registry})
    )

    accepted_keys = [f"k{i}" for i in range(10)]
    for key in accepted_keys:
        glue.put_schema_version_metadata(
            SchemaVersionId=version_id,
            MetadataKeyValue={"MetadataKey": key, "MetadataValue": "v"},
        )

    code, message = _error(
        lambda: glue.put_schema_version_metadata(
            SchemaVersionId=version_id,
            MetadataKeyValue={"MetadataKey": "k10", "MetadataValue": "v"},
        )
    )
    assert code == "ResourceNumberLimitExceededException", (
        f"expected ResourceNumberLimitExceededException, got {code}: {message!r}"
    )
    assert message == "Your resource limits for Schema Version Metadata have been exceeded.", (
        f"unexpected message {message!r}"
    )

    after = glue.query_schema_version_metadata(SchemaVersionId=version_id)
    assert sorted(after["MetadataInfoMap"]) == sorted(accepted_keys), (
        f"expected exactly the 10 accepted keys {sorted(accepted_keys)!r}, "
        f"got {sorted(after['MetadataInfoMap'])!r}"
    )
    assert "k10" not in after["MetadataInfoMap"], "the refused 11th key was nonetheless stored"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
