"""list-schema-versions-single-item-pages-cover-all-created-versions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-schema-versions-single-item-pages-cover-all-created-versions"
GROUP = "pagination"
SERVICES = ["glue"]

_NAMESPACE = "com.example.telemetry"

_V1 = {
    "type": "record",
    "name": "DeviceReading",
    "namespace": _NAMESPACE,
    "fields": [
        {"name": "device_id", "type": "string"},
        {"name": "reading", "type": "double"},
    ],
}

_V2 = {
    "type": "record",
    "name": "DeviceReading",
    "namespace": _NAMESPACE,
    "fields": [
        {"name": "device_id", "type": "string"},
        {"name": "reading", "type": "double"},
        {"name": "unit", "type": "string", "default": "celsius"},
    ],
}

_V3 = {
    "type": "record",
    "name": "DeviceReading",
    "namespace": _NAMESPACE,
    "fields": [
        {"name": "device_id", "type": "string"},
        {"name": "reading", "type": "double"},
        {"name": "unit", "type": "string", "default": "celsius"},
        {"name": "calibrated", "type": "boolean", "default": False},
    ],
}


def _await_available(glue, registry, schema, version_number, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = glue.get_schema_version(
            SchemaId={"RegistryName": registry, "SchemaName": schema},
            SchemaVersionNumber={"VersionNumber": version_number},
        )["Status"]
        if status in ("AVAILABLE", "FAILURE"):
            break
        time.sleep(1)
    assert status == "AVAILABLE", (
        f"version {version_number} of {schema} reached {status!r} before listing, expected AVAILABLE"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchemaVersions with MaxResults=1 returns one entry per page, a NextToken on every
    page but the last, and the pages' union is exactly the versions created, none repeated.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    schema = ctx.unique_name("sim2real-behav-schema-")
    created = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=json.dumps(_V1),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId={"RegistryName": registry, "SchemaName": schema}))
    v1 = created["LatestSchemaVersion"]
    _await_available(glue, registry, schema, v1)

    v2 = glue.register_schema_version(
        SchemaId={"RegistryName": registry, "SchemaName": schema},
        SchemaDefinition=json.dumps(_V2),
    )["VersionNumber"]
    _await_available(glue, registry, schema, v2)

    v3 = glue.register_schema_version(
        SchemaId={"RegistryName": registry, "SchemaName": schema},
        SchemaDefinition=json.dumps(_V3),
    )["VersionNumber"]
    _await_available(glue, registry, schema, v3)

    created_versions = {v1, v2, v3}
    assert len(created_versions) == 3, f"expected 3 distinct version numbers, got {created_versions!r}"

    collected = []
    page_had_next_token = []
    next_token = None
    for _ in range(len(created_versions) + 2):
        kwargs = {"SchemaId": {"RegistryName": registry, "SchemaName": schema}, "MaxResults": 1}
        if next_token is not None:
            kwargs["NextToken"] = next_token
        page = glue.list_schema_versions(**kwargs)
        entries = page["Schemas"]
        assert len(entries) == 1, (
            f"page {len(page_had_next_token) + 1} of ListSchemaVersions with MaxResults=1 "
            f"returned {len(entries)} entries, expected 1"
        )
        collected.append(entries[0]["VersionNumber"])
        next_token = page.get("NextToken")
        page_had_next_token.append(bool(next_token))
        if not next_token:
            break
    else:
        raise AssertionError(f"pagination did not terminate after {len(page_had_next_token)} pages")

    assert len(collected) == 3, f"expected 3 pages of one entry each, got {len(collected)} pages: {collected!r}"
    assert len(set(collected)) == len(collected), (
        f"a version was returned on more than one page: {collected!r}"
    )
    assert set(collected) == created_versions, (
        f"the union of pages was {sorted(set(collected))}, expected the 3 created versions "
        f"{sorted(created_versions)}"
    )
    assert page_had_next_token[:-1] == [True] * (len(page_had_next_token) - 1), (
        f"a page before the last carried no NextToken: {page_had_next_token!r}"
    )
    assert page_had_next_token[-1] is False, (
        f"the last page still carried a NextToken: {page_had_next_token!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
