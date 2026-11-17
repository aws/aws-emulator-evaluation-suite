"""schema-protobuf-forward-field-additions-and-removals."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schema-protobuf-forward-field-additions-and-removals"
GROUP = "schema-compatibility"
SERVICES = ["glue"]

FORWARD_BASE_ADD = (
    'syntax = "proto2";\n'
    "package com.example.logistics;\n"
    "message ShipmentRecord {\n"
    "  required string shipment_id = 1;\n"
    "  required string carrier = 2;\n"
    "  optional string notes = 3;\n"
    "}\n"
)

FORWARD_ADD_OPTIONAL = (
    'syntax = "proto2";\n'
    "package com.example.logistics;\n"
    "message ShipmentRecord {\n"
    "  required string shipment_id = 1;\n"
    "  required string carrier = 2;\n"
    "  optional string notes = 3;\n"
    "  optional string zone = 4;\n"
    "}\n"
)

FORWARD_ADD_REQUIRED = (
    'syntax = "proto2";\n'
    "package com.example.logistics;\n"
    "message ShipmentRecord {\n"
    "  required string shipment_id = 1;\n"
    "  required string carrier = 2;\n"
    "  optional string notes = 3;\n"
    "  required string zone = 4;\n"
    "}\n"
)

FORWARD_BASE_REMOVE = (
    'syntax = "proto2";\n'
    "package com.example.logistics;\n"
    "message ShipmentRecord {\n"
    "  required string shipment_id = 1;\n"
    "  required string carrier = 2;\n"
    "  optional string notes = 3;\n"
    "  required string zone = 4;\n"
    "}\n"
)

FORWARD_REMOVE_OPTIONAL = (
    'syntax = "proto2";\n'
    "package com.example.logistics;\n"
    "message ShipmentRecord {\n"
    "  required string shipment_id = 1;\n"
    "  required string carrier = 2;\n"
    "  required string zone = 4;\n"
    "}\n"
)

FORWARD_REMOVE_REQUIRED = (
    'syntax = "proto2";\n'
    "package com.example.logistics;\n"
    "message ShipmentRecord {\n"
    "  required string shipment_id = 1;\n"
    "  required string carrier = 2;\n"
    "  optional string notes = 3;\n"
    "}\n"
)


def _await_terminal(glue, registry, schema, version_number, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = glue.get_schema_version(
            SchemaId={"RegistryName": registry, "SchemaName": schema},
            SchemaVersionNumber={"VersionNumber": version_number},
        )["Status"]
        if status in ("AVAILABLE", "FAILURE"):
            return status
        time.sleep(1)
    raise AssertionError(
        f"schema version {version_number} of {schema} never reached a terminal status (last={status!r})"
    )


def _register_and_await(glue, registry, schema, definition):
    resp = glue.register_schema_version(
        SchemaId={"RegistryName": registry, "SchemaName": schema},
        SchemaDefinition=definition,
    )
    version_number = resp["VersionNumber"]
    return version_number, _await_terminal(glue, registry, schema, version_number)


def _version_statuses(glue, registry, schema):
    pages = glue.get_paginator("list_schema_versions").paginate(
        SchemaId={"RegistryName": registry, "SchemaName": schema}
    )
    return {item["VersionNumber"]: item["Status"] for page in pages for item in page["Schemas"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Under FORWARD, a proto2 version adding either an optional or a required field, or removing
    an optional field, reaches AVAILABLE; removing a required field reaches FAILURE; and
    ListSchemaVersions reports every version's status to match.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    expected = {}

    schema_add_optional = ctx.unique_name("sim2real-behav-schema-addopt-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_add_optional,
        DataFormat="PROTOBUF",
        Compatibility="FORWARD",
        SchemaDefinition=FORWARD_BASE_ADD,
        Tags={"sim2real": CHECK},
    )
    base_status = _await_terminal(glue, registry, schema_add_optional, 1)
    assert base_status == "AVAILABLE", f"base version of {schema_add_optional} was {base_status!r}"
    v2, status_add_optional = _register_and_await(glue, registry, schema_add_optional, FORWARD_ADD_OPTIONAL)
    assert status_add_optional == "AVAILABLE", (
        f"adding an optional field under FORWARD gave {status_add_optional!r}, expected AVAILABLE"
    )
    expected[schema_add_optional] = {1: "AVAILABLE", v2: "AVAILABLE"}

    schema_add_required = ctx.unique_name("sim2real-behav-schema-addreq-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_add_required,
        DataFormat="PROTOBUF",
        Compatibility="FORWARD",
        SchemaDefinition=FORWARD_BASE_ADD,
        Tags={"sim2real": CHECK},
    )
    base_status = _await_terminal(glue, registry, schema_add_required, 1)
    assert base_status == "AVAILABLE", f"base version of {schema_add_required} was {base_status!r}"
    v2, status_add_required = _register_and_await(glue, registry, schema_add_required, FORWARD_ADD_REQUIRED)
    assert status_add_required == "AVAILABLE", (
        f"adding a required field under FORWARD gave {status_add_required!r}, expected AVAILABLE"
    )
    expected[schema_add_required] = {1: "AVAILABLE", v2: "AVAILABLE"}

    schema_remove_optional = ctx.unique_name("sim2real-behav-schema-rmopt-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_remove_optional,
        DataFormat="PROTOBUF",
        Compatibility="FORWARD",
        SchemaDefinition=FORWARD_BASE_REMOVE,
        Tags={"sim2real": CHECK},
    )
    base_status = _await_terminal(glue, registry, schema_remove_optional, 1)
    assert base_status == "AVAILABLE", f"base version of {schema_remove_optional} was {base_status!r}"
    v2, status_remove_optional = _register_and_await(glue, registry, schema_remove_optional, FORWARD_REMOVE_OPTIONAL)
    assert status_remove_optional == "AVAILABLE", (
        f"removing an optional field under FORWARD gave {status_remove_optional!r}, expected AVAILABLE"
    )
    expected[schema_remove_optional] = {1: "AVAILABLE", v2: "AVAILABLE"}

    schema_remove_required = ctx.unique_name("sim2real-behav-schema-rmreq-")
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_remove_required,
        DataFormat="PROTOBUF",
        Compatibility="FORWARD",
        SchemaDefinition=FORWARD_BASE_REMOVE,
        Tags={"sim2real": CHECK},
    )
    base_status = _await_terminal(glue, registry, schema_remove_required, 1)
    assert base_status == "AVAILABLE", f"base version of {schema_remove_required} was {base_status!r}"
    v2, status_remove_required = _register_and_await(glue, registry, schema_remove_required, FORWARD_REMOVE_REQUIRED)
    assert status_remove_required == "FAILURE", (
        f"removing a required field under FORWARD gave {status_remove_required!r}, expected FAILURE"
    )
    expected[schema_remove_required] = {1: "AVAILABLE", v2: "FAILURE"}

    for schema_name, statuses in expected.items():
        actual = _version_statuses(glue, registry, schema_name)
        for version_number, expected_status in statuses.items():
            assert actual.get(version_number) == expected_status, (
                f"ListSchemaVersions for {schema_name} version {version_number} reported "
                f"{actual.get(version_number)!r}, expected {expected_status!r} (full: {actual!r})"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
