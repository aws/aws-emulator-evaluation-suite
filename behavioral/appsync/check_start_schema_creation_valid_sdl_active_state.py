"""start-schema-creation-valid-sdl-active-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-schema-creation-valid-sdl-active-state"
GROUP = "state"
SERVICES = ["appsync"]

SDL = (
    "type Query {\n"
    "  greeting(name: String): String\n"
    "}\n\n"
    "schema {\n"
    "  query: Query\n"
    "}\n"
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaCreation with valid SDL transitions GetSchemaCreationStatus to
    SUCCESS/ACTIVE, and the compiled Query type retrievable via GetType contains
    exactly the field we defined."""
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav": "start-schema-creation-valid-sdl-active-state"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))

    deadline = time.monotonic() + 90
    status = "PROCESSING"
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE", "FAILED"):
            break
        time.sleep(2.0)
    assert status in ("SUCCESS", "ACTIVE"), f"expected success, got {status}"

    type_def = appsync.get_type(apiId=api_id, typeName="Query", format="SDL")["type"]
    assert type_def["name"] == "Query", f"expected type name Query, got {type_def['name']!r}"
    assert "greeting" in type_def["definition"], type_def["definition"]
    assert "name: String" in type_def["definition"], type_def["definition"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
