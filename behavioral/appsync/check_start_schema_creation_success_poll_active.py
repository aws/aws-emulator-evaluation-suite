"""start-schema-creation-success-poll-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "start-schema-creation-success-poll-active"
GROUP = 'schema'
SERVICES = ['appsync']
DEFAULT_SCHEMA = """schema {
    query: Query
}

type Query {
    getWidget(id: ID!): Widget
    getWidget2(id: ID!): Widget
}

type Widget {
    id: ID!
    name: String
}
"""

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaCreation transitions to a terminal success state and GetIntrospectionSchema then works."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    status = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    final = status.get("status")
    assert final in ("SUCCESS", "ACTIVE"), f"schema creation ended in {final!r}, details={status.get('details')!r}"

    schema_field = svc.get_introspection_schema(apiId=api_id, format="SDL")["schema"]
    schema_bytes = schema_field.read() if hasattr(schema_field, "read") else schema_field
    schema_text = schema_bytes.decode("utf-8") if isinstance(schema_bytes, bytes) else schema_bytes
    assert "getWidget(" in schema_text, f"missing getWidget field in returned schema: {schema_text!r}"
    assert "getWidget2(" in schema_text, f"missing getWidget2 field in returned schema: {schema_text!r}"

    # The definition was parsed into types, not stored verbatim: each type is addressable.
    widget = svc.get_type(apiId=api_id, typeName="Widget", format="SDL")["type"]
    assert widget.get("name") == "Widget", f"GetType(Widget) returned name {widget.get('name')!r}"
    type_names, token = set(), None
    while True:
        page = svc.list_types(apiId=api_id, format="SDL", **({"nextToken": token} if token else {}))
        type_names |= {t.get("name") for t in page.get("types", [])}
        token = page.get("nextToken")
        if not token:
            break
    assert {"Query", "Widget"} <= type_names, f"ListTypes is missing Query/Widget: {sorted(type_names, key=str)!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
