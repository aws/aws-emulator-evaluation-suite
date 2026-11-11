"""describe-schema-specific-version-returns-original-content."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "describe-schema-specific-version-returns-original-content"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSchema with an explicit SchemaVersion always returns that historical version's exact content."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    contents = [_openapi3_content("Widget", n) for n in range(3)]
    schemas.create_schema(RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=contents[0])
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))
    schemas.update_schema(RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=contents[1])
    schemas.update_schema(RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=contents[2])

    for version_str, expected_content in zip(("1", "2", "3"), contents):
        described = schemas.describe_schema(
            RegistryName=registry, SchemaName=schema_name, SchemaVersion=version_str
        )
        assert described["SchemaVersion"] == version_str, (
            f"expected DescribeSchema(SchemaVersion={version_str!r}) to echo that version, "
            f"got {described['SchemaVersion']!r}"
        )
        assert json.loads(described["Content"]) == json.loads(expected_content), (
            f"expected DescribeSchema(SchemaVersion={version_str!r}) to return the content recorded "
            f"for that version, got {described['Content']!r} instead of {expected_content!r}"
        )


def _openapi3_content(title: str, marker: int) -> str:
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}, "marker": {"type": "integer", "enum": [marker]}},
                    }
                }
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
