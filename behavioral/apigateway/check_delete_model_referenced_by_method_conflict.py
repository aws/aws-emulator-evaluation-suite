"""delete-model-referenced-by-method-conflict."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-model-referenced-by-method-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a model still referenced by a method's requestModels must fail with ConflictException."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    model_name = "Sim2RealBehavRefModel" + ctx.unique_name("").replace("-", "")[:8]
    schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
    )
    ag.create_model(
        restApiId=api_id, name=model_name, contentType="application/json", schema=schema
    )

    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="pets")["id"]
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
        requestModels={"application/json": model_name},
    )

    code, message = _error(lambda: ag.delete_model(restApiId=api_id, modelName=model_name))
    assert code == "ConflictException", (
        f"expected ConflictException deleting a model referenced by a method, got {code}"
    )
    assert message == (
        f"Cannot delete model '{model_name}', is referenced in method request: /pets/POST"
    ), f"unexpected message: {message!r}"
    # The rejected delete must not have taken effect: an independent read still finds the model.
    assert ag.get_model(restApiId=api_id, modelName=model_name)["name"] == model_name, (
        "model should still exist after its delete was rejected"
    )

    # Release the reference, then confirm the model actually deletes.
    ag.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST")
    ag.delete_model(restApiId=api_id, modelName=model_name)
    code2, code2_message = _error(lambda: ag.get_model(restApiId=api_id, modelName=model_name))
    assert code2 == "NotFoundException", f"expected model gone, got {code2}"
    assert code2_message == f"Invalid model name specified: {model_name}", f"unexpected message: {code2_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
