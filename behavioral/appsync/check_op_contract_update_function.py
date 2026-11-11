"""op-contract-update-function."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-function"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFunction applies new name/template while preserving identity, and
    rejects a reference to a non-existent data source with NotFoundException without
    mutating the function."""
    appsync = ctx.client("appsync")

    api = appsync.create_graphql_api(name=ctx.unique_name("sim2real-appsync-"), authenticationType="API_KEY")[
        "graphqlApi"
    ]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    ds_name = _sdl_name(ctx, "ds")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    func_name = _sdl_name(ctx, "fn")
    created = appsync.create_function(
        apiId=api_id,
        name=func_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["functionConfiguration"]
    function_id = created["functionId"]
    function_arn = created["functionArn"]

    # success path: rename and change the response template
    new_name = func_name + "v2"
    new_response_template = '$util.toJson({"wrapped": $ctx.result})'
    updated = appsync.update_function(
        apiId=api_id,
        name=new_name,
        functionId=function_id,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate=new_response_template,
    )["functionConfiguration"]
    assert updated["name"] == new_name, f"expected name={new_name!r}, got {updated['name']!r}"
    assert updated["responseMappingTemplate"] == new_response_template, (
        f"expected responseMappingTemplate={new_response_template!r}, "
        f"got {updated['responseMappingTemplate']!r}"
    )
    assert updated["functionId"] == function_id, "functionId must remain stable across update"
    assert updated["functionArn"] == function_arn, "functionArn must remain stable across update"

    fetched = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert fetched["name"] == new_name, f"expected name={new_name!r}, got {fetched['name']!r}"
    assert fetched["responseMappingTemplate"] == new_response_template, (
        f"expected responseMappingTemplate={new_response_template!r}, "
        f"got {fetched['responseMappingTemplate']!r}"
    )
    assert fetched["dataSourceName"] == ds_name, (
        f"expected dataSourceName={ds_name!r}, got {fetched['dataSourceName']!r}"
    )

    # error boundary: dataSourceName referencing a data source that does not exist
    bogus_ds = _sdl_name(ctx, "missing")
    code, message = _error_code(
        lambda: appsync.update_function(
            apiId=api_id,
            name="should_not_apply",
            functionId=function_id,
            dataSourceName=bogus_ds,
            functionVersion="2018-05-29",
            requestMappingTemplate="{}",
            responseMappingTemplate=new_response_template,
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected_message = "Data source not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unaffected = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert unaffected["name"] == new_name, "rejected update must not mutate the function"
    assert unaffected["dataSourceName"] == ds_name, "rejected update must not change dataSourceName"


def _sdl_name(ctx: Any, kind: str) -> str:
    """AppSync identifiers like function/data-source names must match [_A-Za-z][_0-9A-Za-z]*."""
    raw = ctx.unique_name(f"sim2real_{kind}_")
    return raw.replace("-", "_")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
