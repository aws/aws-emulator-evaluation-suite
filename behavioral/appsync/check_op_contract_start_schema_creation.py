"""op-contract-startSchemaCreation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-startSchemaCreation"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA = b"""
type Query {
  ping: String
}

schema {
  query: Query
}
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaCreation drives the schema from PROCESSING to a terminal ACTIVE/SUCCESS status, and the resulting schema is retrievable via GetIntrospectionSchema; a bogus (malformed) apiId is rejected with BadRequestException and never starts a schema creation."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, appsync)

    start_resp = appsync.start_schema_creation(apiId=api_id, definition=_SCHEMA)
    assert start_resp["status"] in ("PROCESSING", "SUCCESS", "ACTIVE"), start_resp["status"]

    final_status = _wait_for_schema(ctx, appsync, api_id)
    assert final_status in ("SUCCESS", "ACTIVE"), f"schema creation ended in {final_status}"

    schema_bytes = appsync.get_introspection_schema(apiId=api_id, format="SDL")["schema"].read()
    assert b"ping" in schema_bytes, schema_bytes

    bogus_api_id = "bogus_api_id_00000"
    code, message = _error(lambda: appsync.start_schema_creation(apiId=bogus_api_id, definition=_SCHEMA))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == f"Invalid API ID {bogus_api_id}", message


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, appsync):
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY", tags={"env": "sim2real-behav"})
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _wait_for_schema(ctx, appsync, api_id, timeout_s=60.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"schema creation did not reach a terminal status in {timeout_s}s, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
