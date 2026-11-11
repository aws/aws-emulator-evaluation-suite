"""op-contract-listTypes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-listTypes"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA = b"""
type Widget {
  id: ID!
  name: String
}

type Query {
  hello: String
  widget: Widget
}

schema {
  query: Query
}
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTypes returns every schema type, including custom object types and one added by CreateType (which
    returns its name), in the requested SDL format; a bogus apiId and a deleted apiId are rejected with
    NotFoundException 'API not found.'."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, appsync)
    _create_schema(ctx, appsync, api_id, _SCHEMA)

    definition = "type Gadget {\n  id: ID!\n  label: String\n}\n"
    created = appsync.create_type(apiId=api_id, definition=definition, format="SDL")["type"]
    assert created["name"] == "Gadget", f"expected created type named Gadget, got {created['name']!r}"

    names = set()
    next_token = None
    while True:
        kwargs = {"apiId": api_id, "format": "SDL"}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = appsync.list_types(**kwargs)
        for t in resp["types"]:
            names.add(t["name"])
            if t["name"] == "Widget":
                assert "name: String" in t["definition"], (
                    f"expected 'name: String' in Widget definition, got {t['definition']!r}"
                )
                assert t["format"] == "SDL", f"expected format SDL, got {t['format']!r}"
            if t["name"] == "Gadget":
                assert t["format"] == "SDL", f"expected format SDL for Gadget, got {t['format']!r}"
        next_token = resp.get("nextToken")
        if not next_token:
            break

    assert {"Query", "Widget", "Gadget"}.issubset(names), f"expected Query, Widget and Gadget, got {names}"

    code, message = _error_code(lambda: appsync.list_types(apiId="bogus_api_id_00000", format="SDL"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected_message = "API not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A well-formed apiId whose API was deleted is not found either.
    ghost_id = _ghost_api_id(ctx, appsync)
    code, message = _error_code(lambda: appsync.list_types(apiId=ghost_id, format="SDL"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _ghost_api_id(ctx, appsync) -> str:
    """Create a GraphQL API and delete it; return its id."""
    ghost_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-ghost-"), authenticationType="API_KEY", tags={"env": "test"}
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _delete_api_if_present(appsync, ghost_id))
    appsync.delete_graphql_api(apiId=ghost_id)
    return ghost_id


def _delete_api_if_present(appsync, api_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_graphql_api(apiId=api_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, appsync):
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY", tags={"env": "test"})
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_schema(ctx, appsync, api_id, definition, timeout_s=60.0, interval_s=1.5):
    appsync.start_schema_creation(apiId=api_id, definition=definition)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE", "FAILED"):
            break
        time.sleep(interval_s)
    if status not in ("SUCCESS", "ACTIVE"):
        raise AssertionError(f"schema creation did not reach SUCCESS/ACTIVE, last status={status}")
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
