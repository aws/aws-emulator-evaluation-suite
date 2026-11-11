"""get-discovered-schema-infers-openapi-from-events."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-discovered-schema-infers-openapi-from-events"
GROUP = "data-plane"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDiscoveredSchema infers a schema whose properties reflect the sampled event payloads' fields."""
    schemas = ctx.client("schemas")
    events = [
        json.dumps({"widgetId": "w-1", "widgetName": "Sprocket", "widgetPrice": 9.99}),
        json.dumps({"widgetId": "w-2", "widgetName": "Cog", "widgetPrice": 19.5}),
    ]

    resp = schemas.get_discovered_schema(Events=events, Type="OpenApi3")
    content = resp["Content"]
    parsed = json.loads(content)
    assert isinstance(parsed, dict), f"expected a JSON object, got {type(parsed).__name__}: {content!r}"
    openapi_version = parsed.get("openapi", "")
    assert openapi_version.startswith("3."), f"expected an OpenAPI 3.x document, got openapi={openapi_version!r}"

    properties = parsed["components"]["schemas"]["Event"]["properties"]
    expected_types = {"widgetId": "string", "widgetName": "string", "widgetPrice": "number"}
    for field, expected_type in expected_types.items():
        assert field in properties, f"expected inferred property {field!r} in discovered schema, got {sorted(properties)}"
        actual_type = properties[field].get("type")
        assert actual_type == expected_type, (
            f"expected sampled field {field!r} to infer type {expected_type!r}, got {actual_type!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
