"""delete-function-referenced-by-pipeline-resolver-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "delete-function-referenced-by-pipeline-resolver-fails"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFunction on a Function still referenced by a PIPELINE resolver is rejected
    BadRequestException, the function is provably still there, and removing the reference
    restores the identical delete to success."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(
        apiId=api_id,
        definition=b"schema { query: Query }\ntype Query { echo: String }",
    )
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90,
        interval_s=2.0,
        description="schema creation to reach a terminal state",
    )

    # DataSource/Function names must match ^[_A-Za-z][_0-9A-Za-z]*$ (no hyphens).
    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    # Positive control: an unreferenced function deletes cleanly, proving the account/API
    # accepts DeleteFunction at all, before the negative below claims a specific rejection.
    control_fn_id = svc.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_behav_fn_ctrl_").replace("-", "_"),
        dataSourceName=ds_name,
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]["functionId"]
    svc.delete_function(apiId=api_id, functionId=control_fn_id)
    control_err = _error(lambda: svc.get_function(apiId=api_id, functionId=control_fn_id))
    assert control_err == ("NotFoundException", f"function id {control_fn_id} not found"), (
        f"positive control: expected an unreferenced function to delete cleanly, "
        f"GetFunction after delete returned {control_err!r}"
    )

    # Functions/resolvers are not independently taggable (no `tags` field on Create*), so no
    # on_cleanup is registered for them: both are deleted explicitly below, and deleting the
    # api cascades over anything left if an assertion raises first.
    fn = svc.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_behav_fn_").replace("-", "_"),
        dataSourceName=ds_name,
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]

    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        kind="PIPELINE",
        pipelineConfig={"functions": [function_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    err = _error(lambda: svc.delete_function(apiId=api_id, functionId=function_id))
    assert err == (
        "BadRequestException",
        "Cannot delete a function which is currently used by a resolver. Resolver type: Query, field: echo",
    ), f"expected BadRequestException deleting a function referenced by a PIPELINE resolver, got {err}"

    # Effect-absent: the rejected delete must not have taken effect.
    still_there = svc.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert still_there["functionId"] == function_id, (
        f"function {function_id} is not readable after a rejected DeleteFunction"
    )

    # Restore: remove the reference, then the identical delete call succeeds.
    svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo")
    svc.delete_function(apiId=api_id, functionId=function_id)

    final_err = _error(lambda: svc.get_function(apiId=api_id, functionId=function_id))
    assert final_err == ("NotFoundException", f"function id {function_id} not found"), (
        f"expected NotFoundException reading the function after the restored delete, got {final_err}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
