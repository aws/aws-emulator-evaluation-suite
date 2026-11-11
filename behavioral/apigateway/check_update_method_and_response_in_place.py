"""update-method-and-response-in-place."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-method-and-response-in-place"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethod/UpdateMethodResponse apply JSON-Patch ops without altering the httpMethod identity."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-method-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    apigw.put_method(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="POST",
        authorizationType="NONE",
        apiKeyRequired=False,
    )
    apigw.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="POST", statusCode="200")

    before = apigw.get_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="POST")
    assert before["httpMethod"] == "POST", f"expected httpMethod POST, got {before.get('httpMethod')}"
    assert before["authorizationType"] == "NONE", (
        f"expected pre-patch authorizationType NONE, got {before.get('authorizationType')}"
    )
    assert before["apiKeyRequired"] is False, (
        f"expected pre-patch apiKeyRequired False, got {before.get('apiKeyRequired')}"
    )

    apigw.update_method(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="POST",
        patchOperations=[
            {"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"},
            {"op": "replace", "path": "/apiKeyRequired", "value": "true"},
            {"op": "add", "path": "/requestParameters/method.request.querystring.foo", "value": "false"},
        ],
    )
    after = apigw.get_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="POST")
    assert after["httpMethod"] == "POST", "the httpMethod identity must not change under UpdateMethod"
    assert after["authorizationType"] == "AWS_IAM", (
        f"expected authorizationType AWS_IAM after patch, got {after.get('authorizationType')}"
    )
    assert after["apiKeyRequired"] is True, f"expected apiKeyRequired True after patch, got {after.get('apiKeyRequired')}"
    assert after["requestParameters"] == {"method.request.querystring.foo": False}, (
        f"expected added requestParameters entry to coerce string \"false\" to boolean False, "
        f"got {after.get('requestParameters')}"
    )

    # UpdateMethodResponse patches the same statusCode entry in place (adding a response model).
    apigw.update_method_response(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="POST",
        statusCode="200",
        patchOperations=[{"op": "add", "path": "/responseModels/application~1json", "value": "Empty"}],
    )
    response_after = apigw.get_method_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="POST", statusCode="200"
    )
    assert response_after["statusCode"] == "200", (
        f"expected statusCode 200 to survive the patch, got {response_after.get('statusCode')}"
    )
    assert response_after["responseModels"] == {"application/json": "Empty"}, (
        f"expected the add op to create a single application/json -> Empty model mapping, "
        f"got {response_after.get('responseModels')}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
