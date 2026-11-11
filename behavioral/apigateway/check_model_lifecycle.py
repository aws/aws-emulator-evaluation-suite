"""model-lifecycle."""
from __future__ import annotations

import json
import random
import string
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-lifecycle"
GROUP = 'models-validators'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel -> GetModel reflects the stored schema -> DeleteModel removes it, the id is
    then unreachable for both reads and mutations, and the freed name is reusable."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    model_name = f"Widget{_unique_token()}"
    schema = json.dumps({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": "Widget",
        "type": "object",
        "properties": {"count": {"type": "integer"}},
    })

    ag.create_model(
        restApiId=rest_api_id,
        name=model_name,
        contentType="application/json",
        schema=schema,
    )

    got = ag.get_model(restApiId=rest_api_id, modelName=model_name)
    assert got["name"] == model_name, f"expected name {model_name!r}, got {got.get('name')!r}"
    got_schema = json.loads(got["schema"])
    assert got_schema.get("properties", {}).get("count", {}).get("type") == "integer", (
        f"expected GetModel to reflect the stored schema's 'count' property as integer, "
        f"got schema {got['schema']!r}"
    )

    ag.delete_model(restApiId=rest_api_id, modelName=model_name)

    code, message = _error(lambda: ag.get_model(restApiId=rest_api_id, modelName=model_name))
    assert code == "NotFoundException", f"expected NotFoundException on read of a deleted model, got {code}"
    assert message == f"Invalid model name specified: {model_name}", f"unexpected message {message!r}"

    code, message = _error(
        lambda: ag.update_model(
            restApiId=rest_api_id,
            modelName=model_name,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException on mutation of a deleted model, got {code}"
    )
    assert message == f"Invalid model name specified: {model_name}", f"unexpected message {message!r}"

    recreated = ag.create_model(
        restApiId=rest_api_id,
        name=model_name,
        contentType="application/json",
        schema=schema,
    )
    assert recreated["name"] == model_name, (
        f"expected the freed name {model_name!r} to be reusable after delete, "
        f"got {recreated.get('name')!r}"
    )
    ag.delete_model(restApiId=rest_api_id, modelName=model_name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
