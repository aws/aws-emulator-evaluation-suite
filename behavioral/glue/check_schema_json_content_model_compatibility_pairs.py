"""schema-json-content-model-compatibility-pairs."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schema-json-content-model-compatibility-pairs"
GROUP = "schema-compatibility"
SERVICES = ["glue"]

_SCHEMA_PREFIX = '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object",'

BACKWARD_CLOSED_V1 = (
    _SCHEMA_PREFIX + '"properties":{"orderId":{"type":"string"}},"additionalProperties":false}'
)
BACKWARD_CLOSED_V2 = (
    _SCHEMA_PREFIX
    + '"properties":{"orderId":{"type":"string"},"notes":{"type":"string"}},'
    '"additionalProperties":false}'
)
BACKWARD_OPEN_V1 = (
    _SCHEMA_PREFIX + '"properties":{"orderId":{"type":"string"}},"additionalProperties":true}'
)
BACKWARD_OPEN_V2 = (
    _SCHEMA_PREFIX
    + '"properties":{"orderId":{"type":"string"},"notes":{"type":"string"}},'
    '"additionalProperties":true}'
)

FORWARD_CLOSED_V1 = (
    _SCHEMA_PREFIX
    + '"properties":{"orderId":{"type":"string"},"notes":{"type":"string"}},'
    '"additionalProperties":false}'
)
FORWARD_CLOSED_V2 = (
    _SCHEMA_PREFIX + '"properties":{"orderId":{"type":"string"}},"additionalProperties":false}'
)
FORWARD_OPEN_V1 = (
    _SCHEMA_PREFIX
    + '"properties":{"orderId":{"type":"string"},"notes":{"type":"string"}},'
    '"additionalProperties":true}'
)
FORWARD_OPEN_V2 = (
    _SCHEMA_PREFIX + '"properties":{"orderId":{"type":"string"}},"additionalProperties":true}'
)


def _register_and_resolve(glue, registry: str, schema_name: str, definition: str):
    """(GetSchemaVersion status, GetSchemaByDefinition status) once the new version is terminal."""
    version_number = glue.register_schema_version(
        SchemaId={"RegistryName": registry, "SchemaName": schema_name},
        SchemaDefinition=definition,
    )["VersionNumber"]
    status = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = glue.get_schema_version(
            SchemaId={"RegistryName": registry, "SchemaName": schema_name},
            SchemaVersionNumber={"VersionNumber": version_number},
        )["Status"]
        if status in ("AVAILABLE", "FAILURE"):
            break
        time.sleep(1)
    by_definition_status = glue.get_schema_by_definition(
        SchemaId={"RegistryName": registry, "SchemaName": schema_name},
        SchemaDefinition=definition,
    )["Status"]
    return status, by_definition_status


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding an optional property under BACKWARD, and removing one under FORWARD, each reach
    AVAILABLE on a closed schema and FAILURE on an open one; GetSchemaByDefinition resolves
    every new version with the same status GetSchemaVersion reports.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    backward_closed = ctx.unique_name("sim2real-behav-schema-bc-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=backward_closed,
        DataFormat="JSON",
        Compatibility="BACKWARD",
        SchemaDefinition=BACKWARD_CLOSED_V1,
        Tags={"sim2real": CHECK},
    )
    backward_open = ctx.unique_name("sim2real-behav-schema-bo-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=backward_open,
        DataFormat="JSON",
        Compatibility="BACKWARD",
        SchemaDefinition=BACKWARD_OPEN_V1,
        Tags={"sim2real": CHECK},
    )
    forward_closed = ctx.unique_name("sim2real-behav-schema-fc-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=forward_closed,
        DataFormat="JSON",
        Compatibility="FORWARD",
        SchemaDefinition=FORWARD_CLOSED_V1,
        Tags={"sim2real": CHECK},
    )
    forward_open = ctx.unique_name("sim2real-behav-schema-fo-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=forward_open,
        DataFormat="JSON",
        Compatibility="FORWARD",
        SchemaDefinition=FORWARD_OPEN_V1,
        Tags={"sim2real": CHECK},
    )

    bc_version_status, bc_def_status = _register_and_resolve(
        glue, registry, backward_closed, BACKWARD_CLOSED_V2
    )
    assert bc_version_status == "AVAILABLE" and bc_def_status == "AVAILABLE", (
        f"BACKWARD closed schema {backward_closed!r} adding an optional property: "
        f"version status {bc_version_status!r}, GetSchemaByDefinition status {bc_def_status!r}, "
        f"expected both AVAILABLE"
    )

    bo_version_status, bo_def_status = _register_and_resolve(
        glue, registry, backward_open, BACKWARD_OPEN_V2
    )
    assert bo_version_status == "FAILURE" and bo_def_status == "FAILURE", (
        f"BACKWARD open schema {backward_open!r} adding an optional property: "
        f"version status {bo_version_status!r}, GetSchemaByDefinition status {bo_def_status!r}, "
        f"expected both FAILURE"
    )

    fc_version_status, fc_def_status = _register_and_resolve(
        glue, registry, forward_closed, FORWARD_CLOSED_V2
    )
    assert fc_version_status == "AVAILABLE" and fc_def_status == "AVAILABLE", (
        f"FORWARD closed schema {forward_closed!r} removing an optional property: "
        f"version status {fc_version_status!r}, GetSchemaByDefinition status {fc_def_status!r}, "
        f"expected both AVAILABLE"
    )

    fo_version_status, fo_def_status = _register_and_resolve(
        glue, registry, forward_open, FORWARD_OPEN_V2
    )
    assert fo_version_status == "FAILURE" and fo_def_status == "FAILURE", (
        f"FORWARD open schema {forward_open!r} removing an optional property: "
        f"version status {fo_version_status!r}, GetSchemaByDefinition status {fo_def_status!r}, "
        f"expected both FAILURE"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
