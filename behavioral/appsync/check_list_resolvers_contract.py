"""op-contract-list-resolvers."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-resolvers"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA_SDL = b"""
schema {
  query: Query
}
type Query {
  getPost: String
  getComments: String
}
"""


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResolvers surfaces a created resolver on a type; an unknown typeName 404s."""
    appsync = ctx.client("appsync")
    api_id = _create_ready_graphql_api(ctx, _SCHEMA_SDL)
    ds_name = _ident(ctx, "ds")

    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getPost",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getPost")
        )
    )

    resp = appsync.list_resolvers(apiId=api_id, typeName="Query")
    by_field = {r["fieldName"]: r for r in resp["resolvers"]}
    assert "getPost" in by_field, f"expected getPost in {list(by_field)}"
    assert by_field["getPost"]["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name!r}, got {by_field['getPost']['dataSourceName']!r}"
    )
    assert by_field["getPost"]["kind"] == "UNIT", (
        f"expected kind UNIT, got {by_field['getPost']['kind']!r}"
    )

    # ListResolvers must also reflect a deletion: gone from the list, and the
    # identical delete call now 404s instead of silently no-op'ing.
    appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getPost")
    after_delete = appsync.list_resolvers(apiId=api_id, typeName="Query")
    remaining = [r["fieldName"] for r in after_delete["resolvers"]]
    assert "getPost" not in remaining, f"expected getPost removed, still in {remaining}"
    code, msg = _error(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getPost")
    )
    assert code == "NotFoundException", f"expected NotFoundException on double-delete, got {code}"
    assert msg == "No resolver found.", f"unexpected double-delete message: {msg!r}"

    # Distinct error boundary: a typeName that doesn't exist in the schema.
    code, msg = _error(
        lambda: appsync.list_resolvers(apiId=api_id, typeName="TotallyUnknownType404")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "Type not found.", f"unexpected message: {msg!r}"


def _ident(ctx, prefix: str) -> str:
    return ctx.unique_name(f"sim2real_{prefix}_").replace("-", "_")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_ready_graphql_api(ctx, definition: bytes) -> str:
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    appsync.start_schema_creation(apiId=api_id, definition=definition)

    def _probe():
        return appsync.get_schema_creation_status(apiId=api_id)["status"]

    status = _poll_until(_probe, lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=90.0)
    assert status in ("SUCCESS", "ACTIVE"), f"schema creation ended in {status}"
    return api_id


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
