"""function-crud-lifecycle."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _sanitize(name):
    """AppSync data source/function names must match ^[_A-Za-z][_0-9A-Za-z]*$."""
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not cleaned or not re.match(r"[_A-Za-z]", cleaned[0]):
        cleaned = "n_" + cleaned
    return cleaned

def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")

CHECK = "function-crud-lifecycle"
GROUP = 'function'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction -> Get/List reflect it -> UpdateFunction persists -> DeleteFunction -> Get/Update are NotFound."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    ds = svc.create_data_source(apiId=api_id, name=_sanitize(ctx.unique_name("sim2real-behav-ds_")), type="NONE")["dataSource"]
    ds_name = ds["name"]
    fn_name = _sanitize(ctx.unique_name("sim2real-behav-fn_"))

    created = svc.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        description="v1",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = created["functionId"]

    got = svc.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert got["name"] == fn_name, f"expected name {fn_name!r}, got {got['name']!r}"
    assert got["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name!r}, got {got['dataSourceName']!r}"
    )
    assert got["description"] == "v1", f"expected description 'v1', got {got['description']!r}"

    ids = [f["functionId"] for f in svc.list_functions(apiId=api_id)["functions"]]
    assert function_id in ids, f"functionId {function_id!r} not present in ListFunctions: {ids!r}"

    svc.update_function(
        apiId=api_id,
        name=fn_name,
        functionId=function_id,
        dataSourceName=ds_name,
        description="v2",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )
    got2 = svc.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert got2["description"] == "v2", (
        f"UpdateFunction did not persist: expected description 'v2', got {got2['description']!r}"
    )

    svc.delete_function(apiId=api_id, functionId=function_id)
    code, message = _error(lambda: svc.get_function(apiId=api_id, functionId=function_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException from GetFunction on a deleted functionId, got {code!r}"
    )
    assert message == f"function id {function_id} not found", f"unexpected GetFunction message: {message!r}"

    code, message = _error(
        lambda: svc.update_function(
            apiId=api_id,
            name=fn_name,
            functionId=function_id,
            dataSourceName=ds_name,
            description="v3",
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
            functionVersion="2018-05-29",
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException from UpdateFunction on a deleted functionId, got {code!r}"
    )
    assert message == f"function id {function_id} not found", f"unexpected UpdateFunction message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
