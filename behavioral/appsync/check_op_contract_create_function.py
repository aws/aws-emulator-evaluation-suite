"""op-contract-createFunction."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createFunction"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_JS_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
_REQUEST_CODE = (
    "export function request(ctx) {\n"
    "  return {};\n"
    "}\n"
    "export function response(ctx) {\n"
    "  return ctx.result;\n"
    "}\n"
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction: success contract (functionId/arn/dataSourceName) + NotFoundException boundary."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav-check": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    fn_name = ctx.unique_name("sim2real_fn_").replace("-", "_")
    resp = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        code=_REQUEST_CODE,
        runtime=_JS_RUNTIME,
    )
    fn = resp["functionConfiguration"]
    function_id = fn["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=function_id))

    assert fn["name"] == fn_name
    assert fn["dataSourceName"] == ds_name
    assert api_id in fn["functionArn"]
    assert function_id in fn["functionArn"]
    assert fn["runtime"]["name"] == "APPSYNC_JS"

    fetched = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert fetched["functionId"] == function_id
    assert fetched["dataSourceName"] == ds_name

    # Error boundary: referencing a data source that does not exist -> NotFoundException.
    # Positive control already ran above (the first create_function succeeded), so this
    # negative isolates the missing dependency rather than a broken account/credentials.
    missing_ds_name = "sim2real_does_not_exist_ds"
    fn2_name = ctx.unique_name("sim2real_fn2_").replace("-", "_")
    code, msg = _error(
        lambda: appsync.create_function(
            apiId=api_id,
            name=fn2_name,
            dataSourceName=missing_ds_name,
            code=_REQUEST_CODE,
            runtime=_JS_RUNTIME,
        )
    )
    assert code == "NotFoundException", f"unexpected error code: {code}"
    assert msg == "Data source not found.", f"unexpected message: {msg!r}"

    fn_names_after_failure = {f["name"] for f in appsync.list_functions(apiId=api_id)["functions"]}
    assert fn2_name not in fn_names_after_failure, (
        f"function {fn2_name} must not exist after create_function failed on a missing data source, "
        f"found in list_functions: {fn_names_after_failure}"
    )

    # Restore: create the data source the previous call was missing, then retry the identical
    # call. It must now succeed, proving the earlier NotFoundException was about that missing
    # dependency and not a name/runtime/code rejection in disguise.
    appsync.create_data_source(apiId=api_id, name=missing_ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=missing_ds_name))

    restored = appsync.create_function(
        apiId=api_id,
        name=fn2_name,
        dataSourceName=missing_ds_name,
        code=_REQUEST_CODE,
        runtime=_JS_RUNTIME,
    )["functionConfiguration"]
    restored_id = restored["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=restored_id))
    assert restored["dataSourceName"] == missing_ds_name, (
        f"restored function should reference {missing_ds_name}, got {restored['dataSourceName']}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
