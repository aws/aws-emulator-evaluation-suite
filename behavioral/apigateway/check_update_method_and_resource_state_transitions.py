"""update-method-and-resource-state-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-method-and-resource-state-transitions"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethod and UpdateResource JSON-Patch operations mutate nested
    configuration that is visible on subsequent GetMethod/GetResource reads."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-updmethres-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE", apiKeyRequired=False
    )

    apigw.update_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        patchOperations=[
            {"op": "replace", "path": "/apiKeyRequired", "value": "true"},
            {"op": "add", "path": "/requestParameters/method.request.querystring.foo", "value": "false"},
        ],
    )

    method = apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert method["apiKeyRequired"] is True, "apiKeyRequired patch did not persist"
    assert method["requestParameters"]["method.request.querystring.foo"] is False, (
        f"requestParameters patch did not persist: {method.get('requestParameters')}"
    )

    apigw.update_resource(
        restApiId=api_id,
        resourceId=resource_id,
        patchOperations=[{"op": "replace", "path": "/pathPart", "value": "gadgets"}],
    )

    resource = apigw.get_resource(restApiId=api_id, resourceId=resource_id)
    assert resource["pathPart"] == "gadgets", f"pathPart patch did not persist: {resource}"
    assert resource["path"] == "/gadgets", f"path did not update to reflect new pathPart: {resource}"
    assert resource["id"] == resource_id, "resourceId must remain stable across the rename"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
