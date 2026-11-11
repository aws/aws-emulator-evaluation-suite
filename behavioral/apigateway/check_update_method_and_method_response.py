"""update-method-and-method-response."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-method-and-method-response"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patches to a method's authorizationType/requestParameters and a method response's models land on Get."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )

    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE",
        requestParameters={"method.request.querystring.q": False},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseModels={"application/json": "Empty"},
    )

    model_name = ctx.unique_name("sim2realmodel").replace("-", "")
    apigw.create_model(
        restApiId=api_id, name=model_name, contentType="application/json",
        schema='{"$schema": "http://json-schema.org/draft-04/schema#", "title": "sim2real", "type": "object"}',
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: apigw.delete_model(restApiId=api_id, modelName=model_name))
    )

    before_method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert before_method["httpMethod"] == "GET", f"expected httpMethod GET, got {before_method.get('httpMethod')}"
    assert before_method["authorizationType"] == "NONE", (
        f"expected authorizationType NONE before update, got {before_method.get('authorizationType')}"
    )
    assert before_method["requestParameters"] == {"method.request.querystring.q": False}, (
        f"expected requestParameters {{'method.request.querystring.q': False}} before update, "
        f"got {before_method.get('requestParameters')}"
    )

    apigw.update_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        patchOperations=[
            {"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"},
            {"op": "replace", "path": "/requestParameters/method.request.querystring.q", "value": "true"},
        ],
    )

    after_method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert after_method["httpMethod"] == "GET", "UpdateMethod must not change the http verb identity"
    assert after_method["authorizationType"] == "AWS_IAM", (
        f"expected authorizationType AWS_IAM after update, got {after_method.get('authorizationType')}"
    )
    assert after_method["requestParameters"] == {"method.request.querystring.q": True}, (
        f"expected requestParameters {{'method.request.querystring.q': True}} after update, "
        f"got {after_method.get('requestParameters')}"
    )

    apigw.update_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        patchOperations=[
            {"op": "replace", "path": "/responseModels/application~1json", "value": model_name}
        ],
    )

    method_response = apigw.get_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert method_response["statusCode"] == "200", (
        f"expected statusCode 200 unchanged after patch, got {method_response.get('statusCode')}"
    )
    assert method_response["responseModels"] == {"application/json": model_name}, (
        f"expected responseModels {{'application/json': {model_name!r}}} after patch, "
        f"got {method_response.get('responseModels')}"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
