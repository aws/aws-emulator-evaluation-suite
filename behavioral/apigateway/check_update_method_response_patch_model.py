"""update-method-response-patch-model."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-method-response-patch-model"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethodResponse patches responseModels mapping for a status code."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    created = apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    assert created["statusCode"] == "200", f"expected statusCode '200', got {created.get('statusCode')!r}"
    assert created["responseModels"]["application/json"] == "Empty", (
        f"expected the built-in Empty model before patching, got {created['responseModels']!r}"
    )

    model_name = "Widget" + ctx.unique_name("").replace("-", "")[:8]
    apigw.create_model(
        restApiId=api_id, name=model_name, contentType="application/json",
        schema=json.dumps({"type": "object"}),
    )
    ctx.on_cleanup(lambda: apigw.delete_model(restApiId=api_id, modelName=model_name))

    updated = apigw.update_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        patchOperations=[{"op": "replace", "path": "/responseModels/application~1json", "value": model_name}],
    )
    assert updated["statusCode"] == "200", "UpdateMethodResponse must not change the status code mapping key"
    assert updated["responseModels"]["application/json"] == model_name, (
        f"expected the patch to replace the model with {model_name!r}, got {updated['responseModels']!r}"
    )

    fetched = apigw.get_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert fetched["responseModels"]["application/json"] == model_name, (
        f"independent GetMethodResponse must reflect the patched model {model_name!r}, "
        f"got {fetched['responseModels']!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"), tags={"sim2real": CHECK})
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
