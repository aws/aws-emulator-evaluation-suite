"""op-contract-deleteDataSource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deleteDataSource"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA = """
type Query {
  getX: String
}
""".strip()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataSource: success removes it; BadRequestException while referenced by a resolver,
    with the reference still intact, and success again once the resolver is removed."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"), authenticationType="API_KEY"
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    # Unreferenced data source: deletes cleanly.
    unused_name = ctx.unique_name("sim2real_ds_unused_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=unused_name, type="NONE")
    appsync.delete_data_source(apiId=api_id, name=unused_name)
    code, msg = _error(lambda: appsync.get_data_source(apiId=api_id, name=unused_name))
    assert code == "NotFoundException", f"deleted data source still gettable: {code}"
    assert msg == f"Data source {unused_name} not found", f"unexpected message: {msg!r}"

    # Referenced data source: must be rejected while a resolver depends on it.
    appsync.start_schema_creation(apiId=api_id, definition=_SCHEMA.encode("utf-8"))
    _wait_schema_active(appsync, api_id)

    used_name = ctx.unique_name("sim2real_ds_used_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=used_name, type="NONE")
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appsync.delete_data_source(apiId=api_id, name=used_name))
    )
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getX",
        dataSourceName=used_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson(null)",
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getX")
        )
    )

    code2, msg2 = _error(lambda: appsync.delete_data_source(apiId=api_id, name=used_name))
    assert code2 == "BadRequestException", f"unexpected error code: {code2}"
    assert msg2 == "Resolver for type Query and field getX associated with data source", (
        f"unexpected message: {msg2!r}"
    )

    # Effect-absent: the rejected delete must not have removed it.
    still_there = appsync.get_data_source(apiId=api_id, name=used_name)["dataSource"]
    assert still_there["name"] == used_name, f"data source vanished despite rejected delete: {still_there}"

    # Restore: once the reference is gone, the identical delete call must now succeed.
    appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getX")
    appsync.delete_data_source(apiId=api_id, name=used_name)
    code3, msg3 = _error(lambda: appsync.get_data_source(apiId=api_id, name=used_name))
    assert code3 == "NotFoundException", f"expected NotFoundException after restore-then-delete, got {code3}"
    assert msg3 == f"Data source {used_name} not found", f"unexpected message: {msg3!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    """Teardown for an object the check deletes itself on the restore path."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_schema_active(appsync, api_id, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        info = appsync.get_schema_creation_status(apiId=api_id)
        last_status = info["status"]
        if last_status in ("SUCCESS", "ACTIVE"):
            return last_status
        if last_status == "FAILED":
            raise AssertionError(f"schema creation failed: {info.get('details')}")
        time.sleep(interval_s)
    raise AssertionError(f"schema never became active, last status={last_status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
