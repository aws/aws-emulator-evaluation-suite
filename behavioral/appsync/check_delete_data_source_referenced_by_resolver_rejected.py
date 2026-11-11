"""delete-data-source-referenced-by-resolver-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-data-source-referenced-by-resolver-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataSource is rejected with BadRequestException while a resolver still references it."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    _create_and_wait_schema(ctx, api_id, "type Query {\n  ping: String\n}\n")

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )

    err = _error(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))
    assert err == (
        "BadRequestException",
        "Resolver for type Query and field ping associated with data source",
    ), f"expected the resolver-reference refusal, got {err}"

    # the data source is still intact after the rejected delete
    still_there = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert still_there["name"] == ds_name, f"expected data source {ds_name} to survive the rejected delete, got {still_there.get('name')!r}"

    # once the resolver is removed, deleting the data source succeeds
    appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    appsync.delete_data_source(apiId=api_id, name=ds_name)
    err_after = _error(lambda: appsync.get_data_source(apiId=api_id, name=ds_name))
    assert err_after == ("NotFoundException", f"Data source {ds_name} not found"), (
        f"expected NotFoundException after delete, got {err_after}"
    )


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]
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
