"""op-contract-update-type."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-type"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateType persists a new SDL definition for an existing type, and
    rejects a malformed SDL definition without mutating the type."""
    appsync = ctx.client("appsync")

    api = appsync.create_graphql_api(name=ctx.unique_name("sim2real-appsync-"), authenticationType="API_KEY")[
        "graphqlApi"
    ]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    base_sdl = "type Query { getX: String }\nschema { query: Query }"
    appsync.start_schema_creation(apiId=api_id, definition=base_sdl.encode("utf-8"))
    _wait_for_schema_active(appsync, api_id)

    created = appsync.create_type(
        apiId=api_id, definition="type Foo { id: ID name: String }", format="SDL"
    )["type"]
    assert created["name"] == "Foo", f"expected created type name 'Foo', got {created['name']!r}"

    # success path: extend the type definition with a new field
    #
    # Real AppSync's UpdateType response only reliably carries `format`/`definition`
    # on the returned Type object (unlike CreateType/GetType, it does not echo back
    # `name`/`arn`), so verify the persisted name/definition via a follow-up GetType
    # rather than asserting on unreliable keys of the update response itself.
    new_definition = "type Foo { id: ID name: String description: String }"
    updated = appsync.update_type(apiId=api_id, typeName="Foo", format="SDL", definition=new_definition)["type"]
    assert updated["format"] == "SDL", f"expected update response format 'SDL', got {updated['format']!r}"
    assert "description: String" in updated["definition"], (
        f"expected new field 'description: String' in update response definition, got {updated['definition']!r}"
    )

    fetched = appsync.get_type(apiId=api_id, typeName="Foo", format="SDL")["type"]
    assert fetched["name"] == "Foo", f"expected fetched type name 'Foo', got {fetched['name']!r}"
    assert "description: String" in fetched["definition"], (
        f"expected persisted definition to contain 'description: String', got {fetched['definition']!r}"
    )

    # error boundary: malformed SDL (unterminated block)
    code, message = _error(
        lambda: appsync.update_type(
            apiId=api_id, typeName="Foo", format="SDL", definition="type Foo { id: ID broken"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Unable to parse provided type definition.", f"unexpected BadRequestException message {message!r}"

    unaffected = appsync.get_type(apiId=api_id, typeName="Foo", format="SDL")["type"]
    assert unaffected["definition"] == fetched["definition"], "rejected update must not mutate the type definition"


def _wait_for_schema_active(appsync, api_id: str, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        status = resp["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError(f"schema creation failed: {resp.get('details')}")
        time.sleep(2)
    raise AssertionError(f"schema creation did not complete within {timeout_s}s (last status={status})")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
