"""get-nonexistent-function-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "get-nonexistent-function-not-found"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFunction on a functionId that has already been deleted (a real, correctly-formatted id)
    returns NotFoundException."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY"
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    # DataSource/Function names must match ^[_A-Za-z][_0-9A-Za-z]*$ (no hyphens).
    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    fn = svc.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_behav_fn_").replace("-", "_"),
        dataSourceName=ds_name,
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]
    svc.delete_function(apiId=api_id, functionId=function_id)

    code, message = _error(lambda: svc.get_function(apiId=api_id, functionId=function_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for GetFunction on a deleted functionId, got {code}"
    )
    expected = f"function id {function_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The dead id must also reject a mutation, not just a read.
    delete_code, delete_message = _error(
        lambda: svc.delete_function(apiId=api_id, functionId=function_id)
    )
    assert delete_code == "NotFoundException", (
        f"expected NotFoundException for repeat DeleteFunction on an already-deleted "
        f"functionId, got {delete_code}"
    )
    assert delete_message == "Function not found.", (
        f"unexpected NotFoundException message {delete_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
