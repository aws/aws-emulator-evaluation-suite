"""create-pipeline-resolver-without-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-resolver-without-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

SCHEMA_SDL = "type Query {\n  x: String\n}\n\nschema {\n  query: Query\n}\n"
FUNC_CODE = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return 'ok';\n}\n"
)
TOP_CODE = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.prev.result;\n}\n"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolver with kind=PIPELINE and no pipelineConfig fails BadRequestException and attaches
    no resolver; the identical call with a pipelineConfig naming a real function succeeds."""
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    _create_schema(appsync, api_id, SCHEMA_SDL)
    appsync.create_data_source(apiId=api_id, name="noneDs", type="NONE")
    runtime = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

    error = None
    try:
        appsync.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="x",
            kind="PIPELINE",
            runtime=runtime,
            code=TOP_CODE,
        )
    except ClientError as e:
        error = (e.response["Error"].get("Code"), e.response["Error"].get("Message"))
    else:
        raise AssertionError("expected CreateResolver kind=PIPELINE without pipelineConfig to be rejected, but it SUCCEEDED")
    expected = ("BadRequestException", "PipelineConfig can't be null.")
    assert error == expected, f"expected {expected}, got {error}"
    rejected_resolvers = appsync.list_resolvers(apiId=api_id, typeName="Query")["resolvers"]
    assert rejected_resolvers == [], (
        f"expected no resolver attached to Query.x after the rejected create, got {rejected_resolvers}"
    )

    func_id = appsync.create_function(
        apiId=api_id, name="fn", dataSourceName="noneDs", runtime=runtime, code=FUNC_CODE
    )["functionConfiguration"]["functionId"]
    good = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="x",
        kind="PIPELINE",
        pipelineConfig={"functions": [func_id]},
        runtime=runtime,
        code=TOP_CODE,
    )["resolver"]
    assert good["pipelineConfig"]["functions"] == [func_id], (
        f"expected the positive-control resolver's pipelineConfig to reference {func_id!r}, "
        f"got {good.get('pipelineConfig')}"
    )
    resolvers = appsync.list_resolvers(apiId=api_id, typeName="Query")["resolvers"]
    assert len(resolvers) == 1 and resolvers[0]["fieldName"] == "x", (
        f"expected exactly one resolver on Query.x after the identical call with a valid "
        f"pipelineConfig succeeded, got {resolvers}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
