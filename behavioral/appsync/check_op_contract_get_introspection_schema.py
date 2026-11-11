"""op-contract-getIntrospectionSchema."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getIntrospectionSchema"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIntrospectionSchema renders the applied SDL; an API with no schema yields
    GraphQLSchemaException, and the identical call succeeds once a schema is created."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    _create_and_wait_schema(ctx, api_id, "type Query {\n  hello: String\n}\n")

    schema_text = _read_sdl(appsync, api_id)
    assert "hello" in schema_text, f"expected 'hello' field in applied SDL, got {schema_text!r}"
    assert "Query" in schema_text, f"expected 'Query' type in applied SDL, got {schema_text!r}"

    # distinct boundary: a freshly created API has no schema at all.
    bare_api_id = _create_graphql_api(ctx)
    status = appsync.get_schema_creation_status(apiId=bare_api_id)["status"]
    assert status == "NOT_APPLICABLE", f"expected NOT_APPLICABLE with no schema created, got {status}"

    code, msg = _error(lambda: appsync.get_introspection_schema(apiId=bare_api_id, format="SDL"))
    assert code == "GraphQLSchemaException", f"expected GraphQLSchemaException, got {code}"
    assert msg == (
        "errors=[InvalidSyntaxError{ message=Invalid Syntax ,"
        "locations=[SourceLocation{line=1, column=0}]}]"
    ), f"unexpected message: {msg!r}"

    # restore: creating a schema on that same, previously schema-less API makes the identical
    # call succeed -- the absence above was a fixable state, not a permanent rejection.
    _create_and_wait_schema(ctx, bare_api_id, "type Query {\n  restored: String\n}\n")
    restored_text = _read_sdl(appsync, bare_api_id)
    assert "restored" in restored_text, (
        f"expected the now-schema'd API's identical call to succeed, got {restored_text!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _read_sdl(appsync, api_id: str) -> str:
    return appsync.get_introspection_schema(apiId=api_id, format="SDL")["schema"].read().decode("utf-8")


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
