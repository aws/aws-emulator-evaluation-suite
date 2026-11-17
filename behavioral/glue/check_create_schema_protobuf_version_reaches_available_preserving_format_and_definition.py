"""create-schema-protobuf-version-reaches-available-preserving-format-and-definition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-schema-protobuf-version-reaches-available-preserving-format-and-definition"
GROUP = "schema"
SERVICES = ["glue"]

_PROTOBUF_DEFINITION = (
    'syntax = "proto3";\n\n'
    "message Shipment {\n"
    "  string shipment_id = 1;\n"
    "  int32 weight_grams = 2;\n"
    "}\n"
)


def _teardown(fn, *not_found_codes: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in not_found_codes:
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchema with DataFormat=PROTOBUF echoes DataFormat=PROTOBUF, and the version
    it mints reaches Status=AVAILABLE with DataFormat and SchemaDefinition unchanged.
    """
    glue = ctx.client("glue")

    registry_name = ctx.unique_name("sim2real-glue-reg")
    glue.create_registry(RegistryName=registry_name)
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name}),
            "EntityNotFoundException",
        )
    )

    schema_name = ctx.unique_name("sim2real-glue-schema")
    created = glue.create_schema(
        RegistryId={"RegistryName": registry_name},
        SchemaName=schema_name,
        DataFormat="PROTOBUF",
        Compatibility="NONE",
        SchemaDefinition=_PROTOBUF_DEFINITION,
    )
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: glue.delete_schema(
                SchemaId={"RegistryName": registry_name, "SchemaName": schema_name}
            ),
            "EntityNotFoundException",
        )
    )

    assert created["DataFormat"] == "PROTOBUF", (
        f"create_schema echoed DataFormat={created['DataFormat']!r}, expected 'PROTOBUF'"
    )

    version_id = created["SchemaVersionId"]
    status = created["SchemaVersionStatus"]
    deadline = time.monotonic() + 120
    while status not in ("AVAILABLE", "FAILURE") and time.monotonic() < deadline:
        time.sleep(2)
        status = glue.get_schema_version(SchemaVersionId=version_id)["Status"]

    assert status == "AVAILABLE", (
        f"minted version {version_id} of {schema_name!r} settled at {status!r}, "
        "expected 'AVAILABLE'"
    )

    final = glue.get_schema_version(SchemaVersionId=version_id)
    assert final["DataFormat"] == "PROTOBUF", (
        f"get_schema_version at AVAILABLE reported DataFormat={final['DataFormat']!r}, "
        "expected 'PROTOBUF'"
    )
    assert final["SchemaDefinition"] == _PROTOBUF_DEFINITION, (
        f"get_schema_version at AVAILABLE returned SchemaDefinition={final['SchemaDefinition']!r}, "
        f"expected the definition unchanged from create_schema: {_PROTOBUF_DEFINITION!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
