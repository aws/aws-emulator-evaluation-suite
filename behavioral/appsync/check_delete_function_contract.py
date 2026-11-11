"""op-contract-delete-function."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-function"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFunction succeeds on an unreferenced function (positive control), is blocked
    while a pipeline resolver references a function, leaves that function intact, then
    succeeds once the reference is removed."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api_with_schema(ctx)
    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    # Positive control: deleting an unreferenced function succeeds outright, so a later
    # BadRequestException can only be attributed to the pipeline reference.
    control_fn_id = appsync.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_fn_control_").replace("-", "_"),
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["functionConfiguration"]["functionId"]
    appsync.delete_function(apiId=api_id, functionId=control_fn_id)
    code, code_msg = _error(
        lambda: appsync.get_function(apiId=api_id, functionId=control_fn_id)
    )
    assert code == "NotFoundException", f"control function still gettable after delete: {code}"
    assert code_msg == f"function id {control_fn_id} not found", f"unexpected message: {code_msg!r}"

    fn_name = ctx.unique_name("sim2real_fn_").replace("-", "_")
    fn = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["functionConfiguration"]
    function_id = fn["functionId"]

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        kind="PIPELINE",
        pipelineConfig={"functions": [function_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    # Error boundary: cannot delete a function still referenced by a pipeline resolver.
    code, code_msg = _error(
        lambda: appsync.delete_function(apiId=api_id, functionId=function_id)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert code_msg == "Cannot delete a function which is currently used by a resolver. Resolver type: Query, field: ping", f"unexpected message: {code_msg!r}"

    # The rejected delete must not have removed it.
    still_there = appsync.get_function(apiId=api_id, functionId=function_id)[
        "functionConfiguration"
    ]
    assert still_there["functionId"] == function_id, "function vanished despite rejected delete"

    appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    appsync.delete_function(apiId=api_id, functionId=function_id)

    code, code_msg = _error(
        lambda: appsync.get_function(apiId=api_id, functionId=function_id)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == f"function id {function_id} not found", f"unexpected message: {code_msg!r}"

    # A mutation on the now-dead id also fails, not just the read.
    code, code_msg = _error(
        lambda: appsync.delete_function(apiId=api_id, functionId=function_id)
    )
    assert code == "NotFoundException", f"expected NotFoundException on double-delete, got {code}"
    assert code_msg == "Function not found.", f"unexpected message: {code_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_graphql_api_with_schema(ctx) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"), authenticationType="API_KEY"
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    definition = b"schema { query: Query }\ntype Query { ping: String }\n"
    appsync.start_schema_creation(apiId=api_id, definition=definition)
    deadline = time.monotonic() + 60.0
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("ACTIVE", "SUCCESS", "FAILED"):
            break
        time.sleep(2)
    assert status in ("ACTIVE", "SUCCESS"), f"schema creation ended in status={status}"
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
