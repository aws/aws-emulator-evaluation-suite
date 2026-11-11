"""op-contract-update-resolver."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-resolver"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResolver applies a new response mapping template on a live UNIT
    resolver, and rejects switching kind to PIPELINE without a pipelineConfig."""
    appsync = ctx.client("appsync")

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    sdl = "type Query { echo(msg: String): String }\nschema { query: Query }"
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    _wait_for_schema_active(appsync, api_id)

    ds_name = _sdl_name(ctx, "ds")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    req_tpl = '{"version": "2017-02-28", "payload": $util.toJson($context.arguments)}'
    resp_tpl = "$util.toJson($context.result)"
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=req_tpl,
        responseMappingTemplate=resp_tpl,
    )

    # success path: change the response mapping template on the existing UNIT resolver
    new_resp_tpl = '$util.toJson({"echoed": $context.result})'
    updated = appsync.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate=req_tpl,
        responseMappingTemplate=new_resp_tpl,
    )["resolver"]
    assert updated["responseMappingTemplate"] == new_resp_tpl, (
        f"expected responseMappingTemplate {new_resp_tpl!r} in UpdateResolver's own response, "
        f"got {updated['responseMappingTemplate']!r}"
    )
    assert updated["kind"] == "UNIT", f"expected kind UNIT after update, got {updated['kind']!r}"
    assert updated["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name!r} unchanged by update, got {updated['dataSourceName']!r}"
    )

    fetched = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert fetched["responseMappingTemplate"] == new_resp_tpl, (
        f"expected GetResolver to reflect new responseMappingTemplate {new_resp_tpl!r}, "
        f"got {fetched['responseMappingTemplate']!r}"
    )
    assert fetched["kind"] == "UNIT", f"expected GetResolver kind UNIT, got {fetched['kind']!r}"

    # error boundary: kind=PIPELINE without a pipelineConfig is malformed
    code, message = _error(
        lambda: appsync.update_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="echo",
            kind="PIPELINE",
            requestMappingTemplate=req_tpl,
            responseMappingTemplate=new_resp_tpl,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "PipelineConfig can't be null.", f"unexpected BadRequestException message {message!r}"

    unaffected = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert unaffected["kind"] == "UNIT", "rejected update must not flip resolver kind"
    assert unaffected["dataSourceName"] == ds_name, "rejected update must not clear dataSourceName"


def _sdl_name(ctx: Any, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real_{kind}_")
    return raw.replace("-", "_")


def _wait_for_schema_active(appsync, api_id: str, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        status = resp["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError(f"schema creation failed: {resp.get('details')}")
        time.sleep(2)
    raise AssertionError(f"schema creation did not complete within {timeout_s}s (last status={status})")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
