"""op-contract-get-function."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-function"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunction returns the created function's fields; an unknown functionId 404s."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    ds_name = _ident(ctx, "ds")
    fn_name = _ident(ctx, "fn")

    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    created = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )
    function_id = created["functionConfiguration"]["functionId"]
    ctx.on_cleanup(lambda: appsync.delete_function(apiId=api_id, functionId=function_id))

    resp = appsync.get_function(apiId=api_id, functionId=function_id)
    fc = resp["functionConfiguration"]
    assert fc["name"] == fn_name, f"expected name={fn_name!r}, got {fc.get('name')!r}"
    assert fc["dataSourceName"] == ds_name, (
        f"expected dataSourceName={ds_name!r}, got {fc.get('dataSourceName')!r}"
    )
    assert fc["functionId"] == function_id, (
        f"expected functionId={function_id!r}, got {fc.get('functionId')!r}"
    )
    assert fc["functionArn"].endswith(f"/functions/{function_id}"), (
        f"expected functionArn to end with /functions/{function_id}, got {fc.get('functionArn')!r}"
    )

    # Distinct error boundary: a well-formed but nonexistent functionId. AppSync validates the
    # functionId's shape before checking existence, so a synthetic (e.g. all-zero) id 400s instead
    # of 404ing — flip one character of the real id to keep the shape valid while making it unused.
    bogus_function_id = function_id[:-1] + ("0" if function_id[-1] != "0" else "1")
    code, code_msg = _error(lambda: appsync.get_function(apiId=api_id, functionId=bogus_function_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == f"function id {bogus_function_id} not found", f"unexpected message: {code_msg!r}"


def _ident(ctx, prefix: str) -> str:
    return ctx.unique_name(f"sim2real_{prefix}_").replace("-", "_")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
