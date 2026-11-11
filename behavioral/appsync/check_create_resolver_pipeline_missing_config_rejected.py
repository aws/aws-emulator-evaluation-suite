"""create-resolver-pipeline-missing-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resolver-pipeline-missing-config-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_SCHEMA_SDL = (
    "type Query {\n  getWidget: String\n}\n"
    "schema {\n  query: Query\n}\n"
)
_JS_CODE = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)
_JS_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResolver with kind=PIPELINE and no pipelineConfig fails BadRequestException and attaches
    no resolver; the same shape with a pipelineConfig naming a real function succeeds on the same API."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    _start_schema_and_wait(ctx, api_id, _SCHEMA_SDL)

    error = _error(
        lambda: appsync.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="getWidget",
            kind="PIPELINE",
            code=_JS_CODE,
            runtime=_JS_RUNTIME,
            # pipelineConfig intentionally omitted
        )
    )
    expected = ("BadRequestException", "PipelineConfig can't be null.")
    assert error == expected, f"expected {expected}, got {error}"

    # the invalid resolver was never attached to the field
    not_found = _error(
        lambda: appsync.get_resolver(
            apiId=api_id, typeName="Query", fieldName="getWidget"
        )
    )
    expected = ("NotFoundException", "No resolver found.")
    assert not_found == expected, (
        f"expected no resolver to exist ({expected}), got error {not_found}"
    )

    # positive control: the identical shape WITH a valid pipelineConfig succeeds,
    # proving the rejection above is specific to the missing pipelineConfig and
    # not a target that refuses every PIPELINE CreateResolver call.
    ds_name = "noneDs"
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))
    func_id = appsync.create_function(
        apiId=api_id,
        name="passthrough",
        dataSourceName=ds_name,
        runtime=_JS_RUNTIME,
        code=_JS_CODE,
    )["functionConfiguration"]["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=func_id))

    good = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        kind="PIPELINE",
        pipelineConfig={"functions": [func_id]},
        code=_JS_CODE,
        runtime=_JS_RUNTIME,
    )["resolver"]
    ctx.on_cleanup(
        lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")
    )
    assert good["pipelineConfig"]["functions"] == [func_id], good

    fetched = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")["resolver"]
    assert fetched["kind"] == "PIPELINE", fetched
    assert fetched["pipelineConfig"]["functions"] == [func_id], fetched


def _error(fn):
    """Call fn(); return its botocore Error (code, message).
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, auth_type: str = "API_KEY") -> dict:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _start_schema_and_wait(ctx, api_id: str, definition: str, timeout_s: float = 90.0) -> str:
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=definition.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        status = resp["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return status
        if status == "FAILED":
            raise AssertionError(f"schema creation failed: {resp.get('details')}")
        time.sleep(2)
    raise AssertionError(f"schema creation did not complete in {timeout_s}s, last status={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
