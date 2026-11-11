"""search-schemas-keyword-filters-results."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "search-schemas-keyword-filters-results"
GROUP = "data-plane"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchSchemas matches keywords against schema name/content, not just Description: a keyword embedded

    in the schema Content is found (after search indexing catches up), and an unrelated keyword returns no
    match for that schema.
    """
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    keyword = "kw" + uuid.uuid4().hex[:12]
    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Description="schema used for search test",
        Content=_openapi3_content("Widget", keyword),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    # Search indexing is asynchronous relative to CreateSchema; poll to a bounded timeout.
    deadline = time.monotonic() + 60
    matched_names: set[str] = set()
    while time.monotonic() < deadline:
        matching = schemas.search_schemas(RegistryName=registry, Keywords=keyword)
        matched_names = {s["SchemaName"] for s in matching["Schemas"]}
        if schema_name in matched_names:
            break
        time.sleep(3)
    assert schema_name in matched_names, f"schema never indexed for its content keyword: {matched_names}"

    other_keyword = "kw" + uuid.uuid4().hex[:12]
    non_matching = schemas.search_schemas(RegistryName=registry, Keywords=other_keyword)
    non_matched_names = {s["SchemaName"] for s in non_matching["Schemas"]}
    assert schema_name not in non_matched_names, (
        f"unrelated keyword {other_keyword!r} unexpectedly matched {schema_name}: {non_matched_names}"
    )

    # A search for the schema's own name also matches it (name is indexed too).
    by_name = schemas.search_schemas(RegistryName=registry, Keywords=schema_name)
    by_name_names = {s["SchemaName"] for s in by_name["Schemas"]}
    assert schema_name in by_name_names, f"search by own name {schema_name!r} did not match: {by_name_names}"


def _openapi3_content(title: str, marker: str) -> str:
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}, marker: {"type": "string"}},
                    }
                }
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
