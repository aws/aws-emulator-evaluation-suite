"""introspection-schema-invalid-schema-exception."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "introspection-schema-invalid-schema-exception"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

_VALID_DEFINITION = b"schema { query: Query }\ntype Query { echo: String }"
_INVALID_DEFINITION = b"schema { query: Query }\ntype Query { echo: ThisTypeDoesNotExist }"

def _create_api(ctx, svc):
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    return api["apiId"]

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIntrospectionSchema on an API whose only schema creation FAILED (field of an undefined type)
    fails GraphQLSchemaException, while a valid schema on a separate API is readable."""
    svc = ctx.client("appsync")

    good_api_id = _create_api(ctx, svc)
    svc.start_schema_creation(apiId=good_api_id, definition=_VALID_DEFINITION)
    good = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=good_api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90,
        interval_s=2.0,
        description="valid schema creation to reach a terminal state",
    )
    assert good["status"] in ("SUCCESS", "ACTIVE"), (
        f"positive control: expected a schema with no undefined types to succeed, "
        f"got {good['status']!r}"
    )
    good_schema = svc.get_introspection_schema(apiId=good_api_id, format="SDL")[
        "schema"
    ].read().decode("utf-8")
    assert "echo" in good_schema, (
        f"positive control: expected the successfully-created schema to be readable, got {good_schema!r}"
    )

    api_id = _create_api(ctx, svc)
    svc.start_schema_creation(apiId=api_id, definition=_INVALID_DEFINITION)
    final = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90,
        interval_s=2.0,
        description="schema creation to reach a terminal state",
    )
    assert final["status"] == "FAILED", (
        f"expected a schema referencing an undefined type to reach FAILED, got {final['status']!r}"
    )
    expected_details = (
        "Found 1 problem(s) with the schema:\n"
        "The field type 'ThisTypeDoesNotExist' is not present when resolving type 'Query'."
    )
    assert final.get("details") == expected_details, (
        f"expected FAILED details {expected_details!r}, got {final.get('details')!r}"
    )

    code, message = _error(lambda: svc.get_introspection_schema(apiId=api_id, format="SDL"))
    assert code == "GraphQLSchemaException", (
        f"expected GraphQLSchemaException for GetIntrospectionSchema on an API with no "
        f"ever-successful schema (not NotFoundException), got {code}"
    )
    expected = (
        "errors=[InvalidSyntaxError{ message=Invalid Syntax ,locations=[SourceLocation{line=1, column=0}]}]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
