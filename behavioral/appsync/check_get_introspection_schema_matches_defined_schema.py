"""get-introspection-schema-matches-defined-schema."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-introspection-schema-matches-defined-schema"
GROUP = "state"
SERVICES = ["appsync"]

_FIELD_NAME = "customFieldXYZ123"
_SCHEMA = f"type Query {{\n  {_FIELD_NAME}: String\n}}\n"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIntrospectionSchema returns a schema (in both SDL and JSON introspection
    formats) that actually contains the field submitted via StartSchemaCreation --
    the introspection endpoint reflects real, current schema state."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    _start_schema_and_wait(ctx, api_id, _SCHEMA)

    sdl = appsync.get_introspection_schema(apiId=api_id, format="SDL")["schema"].read().decode(
        "utf-8"
    )
    assert _FIELD_NAME in sdl, sdl

    introspection_json = json.loads(
        appsync.get_introspection_schema(apiId=api_id, format="JSON")["schema"]
        .read()
        .decode("utf-8")
    )
    types = introspection_json["data"]["__schema"]["types"]
    query_type = next(t for t in types if t["name"] == "Query")
    field_names = [f["name"] for f in query_type["fields"]]
    assert _FIELD_NAME in field_names, field_names


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


def _start_schema_and_wait(ctx, api_id, definition, timeout_s=120.0, interval_s=3.0):
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=definition.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        status = resp["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return status
        if status == "FAILED":
            raise AssertionError(f"schema creation FAILED: {resp.get('details')}")
        time.sleep(interval_s)
    raise AssertionError(f"schema creation incomplete after {timeout_s}s, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
