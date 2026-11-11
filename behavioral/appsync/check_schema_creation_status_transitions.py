"""schema-creation-status-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schema-creation-status-transitions"
GROUP = "state"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  ping: String\n}\n"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaCreation drives the schema through PROCESSING to a terminal
    SUCCESS/ACTIVE state, and only then does GetIntrospectionSchema return the
    submitted type -- schema activation is asynchronous, not immediate."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]

    start_resp = appsync.start_schema_creation(
        apiId=api_id, definition=_SCHEMA.encode("utf-8")
    )
    assert start_resp["status"] in ("PROCESSING", "SUCCESS", "ACTIVE"), start_resp

    if start_resp["status"] == "PROCESSING":
        _assert_schema_not_yet_reflected(appsync, api_id)

    final_status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120.0,
        interval_s=2.0,
    )["status"]
    assert final_status in ("SUCCESS", "ACTIVE"), f"schema creation ended in {final_status}"

    schema_resp = appsync.get_introspection_schema(apiId=api_id, format="SDL")
    schema_text = schema_resp["schema"].read().decode("utf-8")
    assert "ping" in schema_text, schema_text


def _assert_schema_not_yet_reflected(appsync, api_id):
    """The API had no prior schema, so while StartSchemaCreation still reports
    PROCESSING, GetIntrospectionSchema must not already reflect the definition
    just submitted -- this is the "only then" half of the asynchrony claim."""
    from botocore.exceptions import ClientError

    try:
        early = (
            appsync.get_introspection_schema(apiId=api_id, format="SDL")["schema"]
            .read()
            .decode("utf-8")
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "GraphQLSchemaException", exc.response
        message = exc.response["Error"].get("Message")
        assert message == (
            "errors=[InvalidSyntaxError{ message=Invalid Syntax ,locations=[SourceLocation{line=1, column=0}]}]"
        ), f"unexpected GraphQLSchemaException message {message!r}"
        return
    assert "ping" not in early, (
        f"introspection already reflected the submitted schema while "
        f"creation was still PROCESSING: {early}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real-check": CHECK},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
