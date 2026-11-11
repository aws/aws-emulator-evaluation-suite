"""op-contract-getType."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getType"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetType returns the applied SDL definition for a schema-derived type; a bogus typeName 404s."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    _create_and_wait_schema(ctx, api_id, "type Query {\n  hello: String\n}\n")

    got = appsync.get_type(apiId=api_id, typeName="Query", format="SDL")["type"]
    assert got["name"] == "Query", f"expected type name 'Query', got {got['name']!r}"
    assert got["format"] == "SDL", f"expected format 'SDL', got {got['format']!r}"
    assert "hello" in got["definition"], got["definition"]

    code, msg = _error(
        lambda: appsync.get_type(apiId=api_id, typeName="DoesNotExist", format="SDL")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "Type not found.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_and_wait_schema(ctx, api_id: str, sdl: str, timeout_s: float = 90.0) -> None:
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = "PROCESSING"
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation FAILED")
        time.sleep(2)
    raise AssertionError(f"schema creation did not complete in {timeout_s}s, last status={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
