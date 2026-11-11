"""op-contract-delete-model."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-model"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModel removes an unreferenced model; deleting a model still referenced by a
    Method's requestModels is rejected with ConflictException, and succeeds once that
    Method reference is removed."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    model_name = "SimParityWidget"
    apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema='{"$schema":"http://json-schema.org/draft-04/schema#","title":"Widget","type":"object"}',
    )

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="POST", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="POST", type="MOCK")
    apigw.update_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="POST",
        patchOperations=[
            {"op": "add", "path": "/requestModels/application~1json", "value": model_name}
        ],
    )
    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    assert method["requestModels"]["application/json"] == model_name, (
        f"expected requestModels to record {model_name!r}, got {method.get('requestModels')!r}"
    )

    # error boundary: model still referenced by the Method's requestModels -> ConflictException
    err = _client_error(lambda: apigw.delete_model(restApiId=api_id, modelName=model_name))
    assert err.get("Code") == "ConflictException", f"expected ConflictException, got {err.get('Code')!r}"
    assert err.get("Message") == f"Cannot delete model '{model_name}', is referenced in method request: //POST", (
        f"expected the exact in-use message, got {err.get('Message')!r}"
    )
    still_there = apigw.get_model(restApiId=api_id, modelName=model_name)["name"]
    assert still_there == model_name, (
        f"expected the rejected delete to leave {model_name!r} in place, got {still_there!r}"
    )

    # positive control: once the Method is removed, delete succeeds
    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    apigw.delete_model(restApiId=api_id, modelName=model_name)
    err2 = _client_error(lambda: apigw.get_model(restApiId=api_id, modelName=model_name))
    assert err2.get("Code") == "NotFoundException", f"expected model gone after delete, got {err2.get('Code')!r}"
    assert err2.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message from GetModel, got {err2.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises rather than
    being reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
