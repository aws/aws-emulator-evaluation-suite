"""delete-graphql-api-cascades-resolver-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-graphql-api-cascades-resolver-not-found"
GROUP = "state"
SERVICES = ["appsync"]

SCHEMA_SDL = "type Query {\n  x: String\n}\n\nschema {\n  query: Query\n}\n"
JS_CODE = (
    "export function request(ctx) {\n  return 'x';\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteGraphqlApi, the API and every resolver/data source that lived
    under it are gone: GetGraphqlApi and GetResolver both 404, even though the
    resolver was confirmed present immediately beforehand."""
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"), authenticationType="API_KEY"
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _delete_quietly(lambda: appsync.delete_graphql_api(apiId=api_id)))
    _create_schema(appsync, api_id, SCHEMA_SDL)
    appsync.create_data_source(apiId=api_id, name="noneDs", type="NONE")
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="x",
        kind="UNIT",
        dataSourceName="noneDs",
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=JS_CODE,
    )

    # confirm present before deletion
    before = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="x")["resolver"]
    assert before["fieldName"] == "x"

    appsync.delete_graphql_api(apiId=api_id)

    api_err = _error(lambda: appsync.get_graphql_api(apiId=api_id))
    assert api_err == ("NotFoundException", "API not found."), f"expected NotFoundException, got {api_err}"

    resolver_err = _error(
        lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="x")
    )
    assert resolver_err == ("NotFoundException", "API not found."), (
        f"expected NotFoundException for resolver on deleted api, got {resolver_err}"
    )

    # not just unreadable: the dead api is also unusable for a mutation that
    # depends on it existing.
    create_err = _error(
        lambda: appsync.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="x",
            kind="UNIT",
            dataSourceName="noneDs",
            runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
            code=JS_CODE,
        )
    )
    assert create_err == ("NotFoundException", "API not found."), (
        f"expected NotFoundException creating a resolver on a deleted api, got {create_err}"
    )


def _create_schema(appsync, api_id, sdl, timeout_s=90.0):
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = "PROCESSING"
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE", "FAILED"):
            break
        time.sleep(2.0)
    if status not in ("SUCCESS", "ACTIVE"):
        raise AssertionError(f"schema creation did not succeed, status={status}")


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_quietly(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
