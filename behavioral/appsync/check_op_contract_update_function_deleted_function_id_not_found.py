"""op-contract-update-function-deleted-function-id-not-found."""
from __future__ import annotations

CHECK = "op-contract-update-function-deleted-function-id-not-found"
GROUP = "error-semantics"
SERVICES = ["appsync"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFunction persists a new responseMappingTemplate, visible via GetFunction.
    UpdateFunction on a well-formed but deleted functionId fails with NotFoundException."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    ds_name = _sanitize(ctx.unique_name("ds"))
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    fn_name = _sanitize(ctx.unique_name("fn"))
    original_response_template = "$util.toJson({})"
    func = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate=original_response_template,
    )["functionConfiguration"]
    func_id = func["functionId"]

    new_response_template = "$util.toJson($ctx.result)"
    updated = appsync.update_function(
        apiId=api_id,
        name=fn_name,
        functionId=func_id,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate=new_response_template,
    )["functionConfiguration"]
    assert updated["responseMappingTemplate"] == new_response_template, (
        f"expected updated response template {new_response_template!r}, got {updated['responseMappingTemplate']!r}"
    )
    assert updated["responseMappingTemplate"] != original_response_template, (
        "update must not echo back the pre-update template"
    )
    assert updated["functionId"] == func_id, "functionId must not change on update"

    fetched = appsync.get_function(apiId=api_id, functionId=func_id)["functionConfiguration"]
    assert fetched["responseMappingTemplate"] == new_response_template, (
        f"GetFunction must see the persisted template {new_response_template!r}, got {fetched['responseMappingTemplate']!r}"
    )

    # A hand-crafted functionId fails format validation with BadRequestException, so
    # create-then-delete a second function in the same API to get a real-but-gone functionId.
    ghost_fn_name = _sanitize(ctx.unique_name("ghost-fn"))
    ghost_func = appsync.create_function(
        apiId=api_id,
        name=ghost_fn_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate=original_response_template,
    )["functionConfiguration"]
    ghost_func_id = ghost_func["functionId"]
    appsync.delete_function(apiId=api_id, functionId=ghost_func_id)

    expected_message = f"function id {ghost_func_id} not found"
    get_code, get_message = _error_code(lambda: appsync.get_function(apiId=api_id, functionId=ghost_func_id))
    assert get_code == "NotFoundException", f"expected GetFunction to see it gone with NotFoundException, got {get_code}"
    assert get_message == expected_message, f"expected GetFunction message {expected_message!r}, got {get_message!r}"

    code, message = _error_code(
        lambda: appsync.update_function(
            apiId=api_id,
            name=ghost_fn_name,
            functionId=ghost_func_id,
            dataSourceName=ds_name,
            functionVersion="2018-05-29",
            requestMappingTemplate="{}",
            responseMappingTemplate=new_response_template,
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == expected_message, f"expected UpdateFunction message {expected_message!r}, got {message!r}"


def _sanitize(name: str) -> str:
    return name.replace("-", "_")


def _error_code(fn):
    """Return the error code and message of fn(); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
