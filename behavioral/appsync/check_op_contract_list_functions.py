"""op-contract-listFunctions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listFunctions"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctions reflects a created pipeline function; a bogus apiId yields NotFoundException."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    fn_name = ctx.unique_name("sim2real_fn_").replace("-", "_")
    created = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
    )["functionConfiguration"]

    functions = appsync.list_functions(apiId=api_id)["functions"]
    assert len(functions) == 1, f"expected 1 function, got {len(functions)}"
    assert functions[0]["functionId"] == created["functionId"], (
        f"expected functionId {created['functionId']!r}, got {functions[0]['functionId']!r}"
    )
    assert functions[0]["name"] == fn_name, (
        f"expected name {fn_name!r}, got {functions[0]['name']!r}"
    )
    assert functions[0]["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name!r}, got {functions[0]['dataSourceName']!r}"
    )

    code, message = _error_code(lambda: appsync.list_functions(apiId="does_not_exist_1234"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected_message = "API not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK}
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
