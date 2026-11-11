"""model-schema-invalid-json-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-schema-invalid-json-rejected"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel with a malformed (non-JSON) schema string must be rejected with
    BadRequestException, the model must NOT be created, and a subsequent CreateModel
    with a valid schema on the same API must succeed (positive control)."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    bad_model_name = ctx.unique_name("Sim2RealBadModel").replace("-", "")
    malformed_schema = '{"title": "broken", "type": "object", '  # truncated / invalid JSON

    err = _client_error(
        lambda: apigw.create_model(
            restApiId=api_id,
            name=bad_model_name,
            contentType="application/json",
            schema=malformed_schema,
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "Invalid model specified: Validation Result: warnings : [], "
        "errors : [Invalid model schema specified]"
    ), (
        f"expected the exact invalid-schema message, got {err.get('Message')!r}"
    )

    # effect absent: the model must not exist
    not_found = _client_error(
        lambda: apigw.get_model(restApiId=api_id, modelName=bad_model_name)
    )
    assert not_found.get("Code") == "NotFoundException", (
        f"model {bad_model_name} should not exist after rejected create, got {not_found.get('Code')!r}"
    )
    assert not_found.get("Message") == f"Invalid model name specified: {bad_model_name}", (
        f"expected the exact NotFound message, got {not_found.get('Message')!r}"
    )

    # positive control: a valid schema on the same API succeeds
    good_model_name = ctx.unique_name("Sim2RealGoodModel").replace("-", "")
    good_schema = json.dumps({"title": "ok", "type": "object"})
    created = apigw.create_model(
        restApiId=api_id,
        name=good_model_name,
        contentType="application/json",
        schema=good_schema,
    )
    ctx.on_cleanup(lambda: apigw.delete_model(restApiId=api_id, modelName=good_model_name))
    assert created["name"] == good_model_name, (
        f"expected create_model to echo name {good_model_name!r}, got {created.get('name')!r}"
    )

    fetched = apigw.get_model(restApiId=api_id, modelName=good_model_name)
    assert json.loads(fetched["schema"]) == json.loads(good_schema), (
        f"expected round-tripped schema {good_schema!r}, got {fetched['schema']!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name)
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
