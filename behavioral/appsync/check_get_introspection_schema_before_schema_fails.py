"""get-introspection-schema-before-schema-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded instead")

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "get-introspection-schema-before-schema-fails"
# AWS answers an introspection of an API with no schema with this parser error text.
_NO_SCHEMA_MESSAGE = (
    "errors=[InvalidSyntaxError{ message=Invalid Syntax ,locations=[SourceLocation{line=1, column=0}]}]"
)
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIntrospectionSchema on an API without a schema fails GraphQLSchemaException (not
    NotFoundException), and succeeds with the real schema once one is created on that API."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"env": "test"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    status = svc.get_schema_creation_status(apiId=api_id)["status"]
    assert status == "NOT_APPLICABLE", (
        f"expected a freshly created API with no schema attempt to report NOT_APPLICABLE, got {status}"
    )

    code, message = _error(lambda: svc.get_introspection_schema(apiId=api_id, format="SDL"))
    assert code == "GraphQLSchemaException", (
        f"expected GraphQLSchemaException before any schema is created, got {code}"
    )
    assert message == _NO_SCHEMA_MESSAGE, f"unexpected GraphQLSchemaException message {message!r}"

    svc.start_schema_creation(
        apiId=api_id, definition=b"schema { query: Query }\ntype Query { hello: String }\n"
    )
    final_status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        description="schema creation to reach a terminal state",
    )
    assert final_status in ("SUCCESS", "ACTIVE"), f"schema creation ended in {final_status}"

    resp = svc.get_introspection_schema(apiId=api_id, format="SDL")
    schema_text = resp["schema"].read().decode("utf-8")
    assert "hello" in schema_text, (
        f"expected the identical call to now return the created schema, got {schema_text!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
