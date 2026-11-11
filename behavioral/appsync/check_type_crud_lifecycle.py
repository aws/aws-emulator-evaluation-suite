"""type-crud-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "type-crud-lifecycle"
GROUP = 'type'
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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateType -> Get/List reflect it -> UpdateType persists -> DeleteType -> GetType is NotFound."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")

    definition_v1 = "type ExtraType {\n  id: ID!\n}\n"
    svc.create_type(apiId=api_id, definition=definition_v1, format="SDL")

    got = svc.get_type(apiId=api_id, typeName="ExtraType", format="SDL")["type"]
    assert got["name"] == "ExtraType", f"expected type name 'ExtraType', got {got['name']!r}"

    names = [t["name"] for t in svc.list_types(apiId=api_id, format="SDL")["types"]]
    assert "ExtraType" in names, f"expected 'ExtraType' in list_types names, got {names!r}"

    definition_v2 = "type ExtraType {\n  id: ID!\n  label: String\n}\n"
    svc.update_type(apiId=api_id, typeName="ExtraType", definition=definition_v2, format="SDL")
    got2 = svc.get_type(apiId=api_id, typeName="ExtraType", format="SDL")["type"]
    assert "label" in got2["definition"], f"expected persisted 'label' field, got definition {got2['definition']!r}"

    svc.delete_type(apiId=api_id, typeName="ExtraType")
    code, msg = _error(lambda: svc.get_type(apiId=api_id, typeName="ExtraType", format="SDL"))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert msg == "Type not found.", f"unexpected message: {msg!r}"

    # the deleted type is also unusable, not merely unreadable: a second delete of the
    # same (now-nonexistent) type must fail the same way, not silently no-op.
    code2, msg2 = _error(lambda: svc.delete_type(apiId=api_id, typeName="ExtraType"))
    assert code2 == "NotFoundException", f"expected NotFoundException on double-delete, got {code2}"
    assert msg2 == "Type not found.", f"unexpected message: {msg2!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
