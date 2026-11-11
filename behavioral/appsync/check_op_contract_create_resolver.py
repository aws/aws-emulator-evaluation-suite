"""op-contract-createResolver."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-createResolver"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA = """
type Query {
  getPost(id: ID!): String
  getPost2(id: ID!): String
}
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolver: success contract (resolverArn/kind/dataSourceName) + BadRequestException boundary."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.start_schema_creation(apiId=api_id, definition=_SCHEMA.encode("utf-8"))
    _wait_schema_active(appsync, api_id)

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    resp = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getPost",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate='$util.toJson("hello")',
    )
    resolver = resp["resolver"]
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getPost")
    )

    assert resolver["typeName"] == "Query", f"expected typeName Query, got {resolver['typeName']}"
    assert resolver["fieldName"] == "getPost", (
        f"expected fieldName getPost, got {resolver['fieldName']}"
    )
    assert resolver["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name}, got {resolver['dataSourceName']}"
    )
    assert resolver["kind"] == "UNIT", f"expected kind UNIT, got {resolver['kind']}"
    assert api_id in resolver["resolverArn"], (
        f"expected apiId {api_id} in resolverArn, got {resolver['resolverArn']}"
    )
    assert "getPost" in resolver["resolverArn"], (
        f"expected fieldName getPost in resolverArn, got {resolver['resolverArn']}"
    )

    fetched = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="getPost")["resolver"]
    assert fetched["dataSourceName"] == ds_name, (
        f"independent read expected dataSourceName {ds_name}, got {fetched['dataSourceName']}"
    )

    # Error boundary: kind=PIPELINE requires pipelineConfig -> BadRequestException.
    code, msg = _error(
        lambda: appsync.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="getPost2",
            kind="PIPELINE",
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson({})",
        )
    )
    assert code == "BadRequestException", f"unexpected error code: {code}"
    assert msg == "PipelineConfig can't be null.", f"unexpected message: {msg!r}"

    # Effect absent: the rejected PIPELINE resolver was never created (independent read).
    not_found_code, not_found_msg = _error(
        lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="getPost2")
    )
    assert not_found_code == "NotFoundException", (
        f"expected no resolver on getPost2 after rejection, got error {not_found_code}"
    )
    assert not_found_msg == "No resolver found.", f"unexpected message: {not_found_msg!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
