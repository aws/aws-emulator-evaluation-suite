"""op-contract-getResolver."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getResolver"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResolver returns the created UNIT resolver's type, field, data source and ARN; a schema field with no
    resolver and a field absent from the schema both yield NotFoundException with the exact message AWS returns."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    _create_and_wait_schema(ctx, api_id, "type Query {\n  ping: String\n  getComments: String\n}\n")

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    created = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )["resolver"]

    got = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")["resolver"]
    assert got["typeName"] == "Query", f"expected typeName Query, got {got['typeName']!r}"
    assert got["fieldName"] == "ping", f"expected fieldName ping, got {got['fieldName']!r}"
    assert got["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name}, got {got['dataSourceName']!r}"
    )
    assert got["kind"] == "UNIT", f"expected kind UNIT, got {got['kind']!r}"
    assert got["resolverArn"] == created["resolverArn"], (
        f"expected resolverArn {created['resolverArn']}, got {got['resolverArn']!r}"
    )

    code, msg = _error(
        lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="doesNotExist")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "No resolver found.", f"unexpected message: {msg!r}"

    # A field the schema defines but no resolver is attached to is refused the same way.
    code, msg = _error(
        lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="getComments")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "No resolver found.", f"unexpected message: {msg!r}"


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
