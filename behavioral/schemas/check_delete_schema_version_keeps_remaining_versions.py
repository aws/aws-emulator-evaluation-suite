"""delete-schema-version-keeps-remaining-versions."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-schema-version-keeps-remaining-versions"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting one schema version removes only that version, the schema and its siblings survive."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget"),
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))
    content_v2 = _openapi3_content("Widget", {"color": {"type": "string"}})
    schemas.update_schema(RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=content_v2)

    schemas.delete_schema_version(RegistryName=registry, SchemaName=schema_name, SchemaVersion="1")

    versions = schemas.list_schema_versions(RegistryName=registry, SchemaName=schema_name)
    remaining = {v["SchemaVersion"] for v in versions["SchemaVersions"]}
    assert remaining == {"2"}, f"expected only version 2 to remain, got {remaining!r}"

    read_err = _error(
        lambda: schemas.describe_schema(RegistryName=registry, SchemaName=schema_name, SchemaVersion="1")
    )
    assert read_err["Code"] == "NotFoundException", f"expected NotFoundException reading deleted version 1, got {read_err!r}"
    assert read_err["Message"] == f"Schema with name {schema_name} and version 1 does not exist.", f"unexpected describe_deleted_version message: {read_err['Message']!r}"

    delete_again = _error(
        lambda: schemas.delete_schema_version(RegistryName=registry, SchemaName=schema_name, SchemaVersion="1")
    )
    assert delete_again["Code"] == "NotFoundException", f"expected NotFoundException re-deleting version 1, got {delete_again!r}"
    assert delete_again["Message"] == f"Schema with name {schema_name} and version 1 does not exist.", f"unexpected delete_version_again message: {delete_again['Message']!r}"

    still_there = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert still_there["SchemaVersion"] == "2", f"expected latest version 2 to survive, got {still_there['SchemaVersion']!r}"
    assert json.loads(still_there["Content"]) == json.loads(
        content_v2
    ), f"expected surviving version's content to match v2, got {still_there['Content']!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _openapi3_content(title: str, extra_props: dict | None = None) -> str:
    props = {"id": {"type": "string"}}
    if extra_props:
        props.update(extra_props)
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {"schemas": {"Event": {"type": "object", "properties": props}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
