"""update-schema-idempotency-token-reuses-version."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "update-schema-idempotency-token-reuses-version"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying UpdateSchema with the same ClientTokenId does not mint a second new version."""
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

    token = uuid.uuid4().hex
    content_v2 = _openapi3_content("Widget", {"color": {"type": "string"}})
    first = schemas.update_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=content_v2,
        ClientTokenId=token,
    )
    assert first["SchemaVersion"] == "2", f"expected the first update to mint version 2, got {first['SchemaVersion']!r}"

    retried = schemas.update_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=content_v2,
        ClientTokenId=token,
    )
    assert retried["SchemaVersion"] == "2", (
        f"retrying UpdateSchema with the same ClientTokenId must reuse version 2, got {retried['SchemaVersion']!r}"
    )

    versions = schemas.list_schema_versions(RegistryName=registry, SchemaName=schema_name)
    all_versions = {v["SchemaVersion"] for v in versions["SchemaVersions"]}
    assert all_versions == {"1", "2"}, f"expected exactly versions 1 and 2 to exist, got {all_versions}"


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
