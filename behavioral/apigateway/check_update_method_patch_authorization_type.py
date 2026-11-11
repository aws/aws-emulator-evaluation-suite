"""update-method-patch-authorization-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-method-patch-authorization-type"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethod changes authorizationType/authorizerId while the http verb stays fixed."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    created = apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    assert created["httpMethod"] == "GET", f"expected httpMethod GET, got {created.get('httpMethod')}"
    assert created["authorizationType"] == "NONE", (
        f"expected authorizationType NONE, got {created.get('authorizationType')}"
    )

    region = ctx.region
    fake_lambda_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{region}:123456789012:function:sim2real-bh-fake-authorizer/invocations"
    )
    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-bh-authz-"),
        type="TOKEN",
        authorizerUri=fake_lambda_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    updated = apigw.update_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        patchOperations=[
            {"op": "replace", "path": "/authorizationType", "value": "CUSTOM"},
            {"op": "replace", "path": "/authorizerId", "value": authorizer_id},
        ],
    )
    assert updated["httpMethod"] == "GET", "UpdateMethod must not change the http verb"
    assert updated["authorizationType"] == "CUSTOM", (
        f"expected authorizationType CUSTOM after patch, got {updated.get('authorizationType')}"
    )
    assert updated["authorizerId"] == authorizer_id, (
        f"expected authorizerId {authorizer_id!r} after patch, got {updated.get('authorizerId')!r}"
    )

    fetched = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["httpMethod"] == "GET", f"independent read: expected httpMethod GET, got {fetched.get('httpMethod')}"
    assert fetched["authorizationType"] == "CUSTOM", (
        f"independent read: expected authorizationType CUSTOM, got {fetched.get('authorizationType')}"
    )
    assert fetched["authorizerId"] == authorizer_id, (
        f"independent read: expected authorizerId {authorizer_id!r}, got {fetched.get('authorizerId')!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"))
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
